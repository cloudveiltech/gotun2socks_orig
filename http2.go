package main

import (
	"bytes"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/cloudveiltech/goproxy"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	tls "github.com/refraction-networking/utls"
)

var http2ProxySessionCounter int64

const MAX_FILTERABLE_LENGTH = 1024 * 1024
const MIN_FILTERABLE_LENGTH = 100

const STATUS_BLOCKED = 0
const STATUS_OK = 1
const STATUS_ENDED = 2

type Http2Handler struct {
	maxFrameSize           uint32
	lastHttpResponse       map[uint32]*http.Response
	lastHttpRequest        map[uint32]*http.Request
	lastHeadersBlock       map[uint32]*http2.HeadersFrameParam
	proxyCtx               map[uint32]*goproxy.ProxyCtx
	lastHeadersMap         map[uint32][]hpack.HeaderField
	responseBodyMapChunks  map[uint32][][]byte
	debouncers             map[uint32]func(f func())
	connectionReadyForData bool
	rwMutex                *sync.RWMutex
}

// returns new path
func HostPathForceSafeSearch(host, path string) string {
	// enforce Google safe-search
	if strings.Contains(host, "google.com") && strings.Contains(path, "/search?") && !strings.Contains(path, "safe=active") {
		return strings.Replace(path+"&safe=active", "&safe=images", "", -1)
		// enforce Bing safe-search
	} else if strings.Contains(host, "bing.com") && strings.Contains(path, "/search?") && !strings.Contains(path, "adlt=strict") {
		return path + "&adlt=strict"
		// enforce Yahoo safe-search
	} else if strings.Contains(host, "yahoo.com") && strings.Contains(path, "/search?") && !strings.Contains(path, "&vm=r") {
		return path + "&vm=r"
	}
	return path
}

func CookiePatchSafeSearch(host, cookieValue string) string {
	if strings.Contains(host, "vimeo") {
		cookieParts := strings.Split(cookieValue, ";")
		newCookieParts := make([]string, 0)
		for _, cookie := range cookieParts {
			if !strings.Contains(cookie, "content_rating") {
				newCookieParts = append(newCookieParts, cookie)
			}
		}

		newCookieParts = append(newCookieParts, "content_rating=7")

		return strings.Join(newCookieParts, ";")
	}
	return cookieValue
}

func serveHttp2Filtering(r *http.Request, rawClientTls *tls.Conn, remote *tls.UConn) bool {
	//log.Print("Running http2 handler for " + r.URL.String())

	http2Handler := &Http2Handler{
		maxFrameSize:           1024,
		lastHttpResponse:       make(map[uint32]*http.Response),
		lastHeadersBlock:       make(map[uint32]*http2.HeadersFrameParam),
		lastHeadersMap:         make(map[uint32][]hpack.HeaderField),
		lastHttpRequest:        make(map[uint32]*http.Request),
		proxyCtx:               make(map[uint32]*goproxy.ProxyCtx),
		responseBodyMapChunks:  make(map[uint32][][]byte),
		debouncers:             make(map[uint32]func(f func())),
		connectionReadyForData: false,
		rwMutex:                &sync.RWMutex{},
	}
	go func() {
		http2Handler.processHttp2Stream(rawClientTls, remote)
	}()

	return true
}

func (http2Handler *Http2Handler) processHttp2Stream(local *tls.Conn, remote *tls.UConn) {
	const preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
	b := make([]byte, len(preface))
	if _, err := io.ReadFull(local, b); err != nil {
		log.Printf("ReadFrame: preface %v", err)
		go func() {
			io.Copy(local, remote)
		}()
		io.Copy(remote, local)
		return
	}
	if string(b) != preface {
		log.Printf("ReadFrame: preface error")
		return
	}
	remote.Write(b)

	http2.VerboseLogs = false
	directFramer := http2.NewFramer(remote, local)
	reverseFramer := http2.NewFramer(local, remote)

	go func() {
		decoder := hpack.NewDecoder(65536, nil)
		for {
			res := http2Handler.readFrame(reverseFramer, directFramer, decoder, false)
			if res != STATUS_OK {
				return
			}
		}
	}()
	decoder := hpack.NewDecoder(65536, nil)
	for {
		res := http2Handler.readFrame(directFramer, reverseFramer, decoder, true)
		if res != STATUS_OK {
			if res == STATUS_BLOCKED {
				remote.Close()
			}
			return
		}
	}
}

func isContentTypeFilterable(contentType string) bool {
	if strings.Contains(contentType, "protobuf") {
		return false
	}
	return strings.Contains(contentType, "html") ||
		strings.Contains(contentType, "json") ||
		strings.Contains(contentType, "image/png") ||
		strings.Contains(contentType, "image/jpg") ||
		strings.Contains(contentType, "image/jpeg") ||
		strings.Contains(contentType, "image/webp")
}

func (http2Handler *Http2Handler) readFrame(directFramer, reverseFramer *http2.Framer, decoder *hpack.Decoder, client bool) int {
	f, err := directFramer.ReadFrame()
	if err != nil {
		//log.Printf("ReadFrame client %v, err: %v", client, err)
		return STATUS_ENDED
	}

	switch f.Header().Type {
	case http2.FrameData:
		fr := f.(*http2.DataFrame)
		body := fr.Data()

		streamId := f.Header().StreamID

		http2Handler.rwMutex.RLock()
		lastHttpResponse := http2Handler.lastHttpResponse[streamId]
		bodyChunks := http2Handler.responseBodyMapChunks[streamId]
		ctx := http2Handler.proxyCtx[streamId]
		http2Handler.rwMutex.RUnlock()

		chunk := make([]byte, len(body))
		copy(chunk, body)
		bodyChunks = append(bodyChunks, chunk)

		http2Handler.rwMutex.Lock()
		http2Handler.responseBodyMapChunks[streamId] = bodyChunks
		http2Handler.rwMutex.Unlock()

		whitelisted := false
		if ctx != nil && ctx.UserData != nil {
			blocked, exists := ctx.UserData.(map[string]interface{})["blocked"]
			whitelisted = exists && !(blocked.(bool))
		}

		processDataFrameFunc := func(force bool, streamId uint32, directFramer, reverseFramer *http2.Framer, decoder *hpack.Decoder, client bool) int {
			if force {
				log.Print("Force ending stream on timeout")
			}
			http2Handler.rwMutex.RLock()
			lastHttpResponse = http2Handler.lastHttpResponse[streamId]
			bodyChunks = http2Handler.responseBodyMapChunks[streamId]
			http2Handler.rwMutex.RUnlock()

			streamEnded := fr.StreamEnded() || force
			if !whitelisted && lastHttpResponse != nil && !client {
				contentType := lastHttpResponse.Header.Get("Content-Type")
				isContentTypeFilterable := isContentTypeFilterable(contentType)
				isImage := strings.Contains(contentType, "image")
				putResponseBody(bodyChunks, lastHttpResponse)
				contentLength := lastHttpResponse.ContentLength

				isContentTypeFilterable = isContentTypeFilterable && (contentLength < MAX_FILTERABLE_LENGTH || isImage)
				if isContentTypeFilterable && streamEnded {
					if contentLength > MIN_FILTERABLE_LENGTH {
						http2Handler.rwMutex.RLock()
						ctx := http2Handler.proxyCtx[streamId]
						http2Handler.rwMutex.RUnlock()
						resp := proxy.FilterResponse(lastHttpResponse, ctx)

						if resp != lastHttpResponse { //new response
							if !http2Handler.connectionReadyForData {
								reverseFramer.WriteSettings()
							}
							writeHeaders(directFramer, &http2.HeadersFrameParam{
								StreamID:      streamId,
								BlockFragment: encodeHeaders(resp),
								EndStream:     false,
								EndHeaders:    true,
								PadLength:     0,
								Priority:      http2.PriorityParam{},
							}, decoder)
							buf := new(bytes.Buffer)
							buf.ReadFrom(resp.Body)
							writeFinalData(directFramer, f.Header().StreamID, buf, int(http2Handler.maxFrameSize))
							//		directFramer.WriteGoAway(streamId, http2.ErrCodeCancel, nil)
							http2Handler.rwMutex.Lock()
							delete(http2Handler.lastHttpResponse, streamId)
							delete(http2Handler.lastHttpRequest, streamId)
							delete(http2Handler.responseBodyMapChunks, streamId)
							http2Handler.rwMutex.Unlock()
							return STATUS_BLOCKED
						}
					}
				} else if isContentTypeFilterable {
					return STATUS_OK
				}
			}

			http2Handler.rwMutex.RLock()
			header, ok := http2Handler.lastHeadersBlock[streamId]
			http2Handler.rwMutex.RUnlock()
			if ok {
				//	headerFields, _ := http2Handler.lastHeadersMap[streamId]
				header.EndStream = false
				//	header.BlockFragment = encodeHeaderFields(headerFields)
				writeHeaders(directFramer, header, decoder)

				http2Handler.rwMutex.Lock()
				delete(http2Handler.lastHeadersBlock, streamId)
				delete(http2Handler.lastHeadersMap, streamId)
				http2Handler.rwMutex.Unlock()
			}

			for i, _ := range bodyChunks {
				streamEnd := i == len(bodyChunks)-1 && streamEnded
				directFramer.WriteData(streamId, streamEnd, bodyChunks[i])
			}

			http2Handler.rwMutex.Lock()
			delete(http2Handler.responseBodyMapChunks, streamId)
			http2Handler.rwMutex.Unlock()
			return STATUS_OK
		}

		processDataFrameFunc(false, streamId, directFramer, reverseFramer, decoder, client)
		/*
			debouncer, exists := http2Handler.debouncers[streamId]
			if !exists {
				debouncer = debounce.New(time.Millisecond * 1000)
				http2Handler.debouncers[streamId] = debouncer
			}
			debouncer(func() {
				_, exists := http2Handler.debouncers[streamId]
				if exists {
					processDataFrameFunc(true, streamId, directFramer, reverseFramer, decoder, client)
				}
			})*/
	case http2.FrameHeaders:
		fr := f.(*http2.HeadersFrame)

		headerFields, _ := decodeAllHeaders(directFramer, fr, decoder)
		if len(headerFields) == 0 {
			log.Printf("Error parsing headers")
		}
		whitelisted := false

		streamId := f.Header().StreamID
		ctx := http2Handler.proxyCtx[streamId]
		if ctx != nil && ctx.UserData != nil {
			blocked, exists := ctx.UserData.(map[string]interface{})["blocked"]
			whitelisted = exists && !(blocked.(bool))
		}

		writeHeadersImmediately := whitelisted || client || fr.StreamEnded()
		if client {
			request := makeHttpRequest(nil, headerFields)
			var ctx = &goproxy.ProxyCtx{Req: request, Session: atomic.AddInt64(&http2ProxySessionCounter, 1)}

			http2Handler.rwMutex.Lock()
			http2Handler.lastHttpRequest[streamId] = request
			http2Handler.proxyCtx[streamId] = ctx
			http2Handler.rwMutex.Unlock()
			_, resp := proxy.FilterRequest(request, ctx)

			if resp != nil {
				if !http2Handler.connectionReadyForData {
					reverseFramer.WriteSettings()
				}
				writeHeaders(reverseFramer, &http2.HeadersFrameParam{
					StreamID:      streamId,
					BlockFragment: encodeHeaders(resp),
					EndStream:     false,
					EndHeaders:    true,
					PadLength:     0,
					Priority:      fr.Priority,
				}, decoder)
				buf := new(bytes.Buffer)
				buf.ReadFrom(resp.Body)

				writeFinalData(reverseFramer, streamId, buf, int(http2Handler.maxFrameSize))
				reverseFramer.WriteGoAway(streamId, http2.ErrCodeRefusedStream, nil)
				return STATUS_BLOCKED
			}
		} else {
			response := makeHttpResponse(nil, headerFields)

			http2Handler.rwMutex.Lock()
			http2Handler.lastHttpResponse[streamId] = response
			http2Handler.lastHttpResponse[streamId].Request = http2Handler.lastHttpRequest[streamId]
			http2Handler.rwMutex.Unlock()

			contentType := response.Header.Get("Content-Type")
			//	contentLength, _ := strconv.Atoi(response.Header.Get("Content-Length"))
			if !isContentTypeFilterable(contentType) {
				writeHeadersImmediately = true
			}
		}

		header := http2.HeadersFrameParam{
			StreamID:      streamId,
			BlockFragment: encodeHeaderFields(headerFields),
			EndStream:     fr.StreamEnded(),
			EndHeaders:    fr.HeadersEnded(),
			PadLength:     0,
			Priority:      fr.Priority,
		}

		if writeHeadersImmediately {
			writeHeaders(directFramer, &header, decoder)
		} else {
			http2Handler.rwMutex.Lock()
			http2Handler.lastHeadersMap[f.Header().StreamID] = headerFields
			http2Handler.lastHeadersBlock[f.Header().StreamID] = &header
			http2Handler.rwMutex.Unlock()
		}
	case http2.FramePriority:
		fr := f.(*http2.PriorityFrame)
		directFramer.WritePriority(f.Header().StreamID, fr.PriorityParam)
	case http2.FrameRSTStream:
		fr := f.(*http2.RSTStreamFrame)
		directFramer.WriteRSTStream(f.Header().StreamID, fr.ErrCode)
	case http2.FrameSettings:
		fr := f.(*http2.SettingsFrame)
		if !client {
			http2Handler.connectionReadyForData = true //once server sent the settings we're good to go
		}

		if fr.IsAck() {
			directFramer.WriteSettingsAck()
		} else {
			params := make([]http2.Setting, 0)
			for i := 0; i < fr.NumSettings(); i++ {
				setting := fr.Setting(i)
				params = append(params, setting)
				if setting.ID == http2.SettingHeaderTableSize && client {
					decoder.SetMaxDynamicTableSize(setting.Val)
				}
				if setting.ID == http2.SettingMaxFrameSize && client {
					if http2Handler.maxFrameSize > setting.Val {
						http2Handler.maxFrameSize = setting.Val
					}
				}

			}
			directFramer.WriteSettings(params...)
		}

	case http2.FramePushPromise:
		fr := f.(*http2.PushPromiseFrame)
		directFramer.WritePushPromise(http2.PushPromiseParam{

			StreamID:      f.Header().StreamID,
			PromiseID:     fr.PromiseID,
			BlockFragment: fr.HeaderBlockFragment(),
			EndHeaders:    fr.HeadersEnded(),
			PadLength:     0,
		})
	case http2.FramePing:
		fr := f.(*http2.PingFrame)
		directFramer.WritePing(fr.IsAck(), fr.Data)
	case http2.FrameGoAway:
		fr := f.(*http2.GoAwayFrame)
		directFramer.WriteGoAway(fr.LastStreamID, fr.ErrCode, fr.DebugData())
	case http2.FrameWindowUpdate:
		fr := f.(*http2.WindowUpdateFrame)
		directFramer.WriteWindowUpdate(f.Header().StreamID, fr.Increment)
	case http2.FrameContinuation:
		fr := f.(*http2.ContinuationFrame)
		directFramer.WriteContinuation(f.Header().StreamID, fr.HeadersEnded(), fr.HeaderBlockFragment())
	default:
		fr := f.(*http2.UnknownFrame)
		directFramer.WriteRawFrame(f.Header().Type, f.Header().Flags, f.Header().StreamID, fr.Payload())
	}

	return STATUS_OK
}

func decodeAllHeaders(framer *http2.Framer, fr *http2.HeadersFrame, decoder *hpack.Decoder) ([]hpack.HeaderField, []byte) {
	buf := new(bytes.Buffer)
	res := make([]hpack.HeaderField, 0)

	hostIndex := 0
	pathIndex := 0
	cookieIndex := 0
	decoder.SetEmitEnabled(true)
	decoder.SetMaxStringLength(16 << 20)
	decoder.SetEmitFunc(func(hf hpack.HeaderField) {
		if len(hf.Name) > 0 {
			if hf.Name == ":path" {
				pathIndex = len(res)
			} else if hf.Name == ":authority" {
				hostIndex = len(res)
			} else if hf.Name == "cookie" {
				cookieIndex = len(res)
			}
			res = append(res, hf)
		}
	})
	defer decoder.SetEmitFunc(func(hf hpack.HeaderField) {})
	defer decoder.Close()

	buf.Write(fr.HeaderBlockFragment())
	_, err := decoder.Write(fr.HeaderBlockFragment())
	if err != nil {
		log.Printf("Error decode %v", err)
	}
	if fr.HeadersEnded() {
		if hostIndex > 0 || pathIndex > 0 {
			res[pathIndex].Value = HostPathForceSafeSearch(res[hostIndex].Value, res[pathIndex].Value)

			if cookieIndex > 0 {
				res[cookieIndex].Value = CookiePatchSafeSearch(res[hostIndex].Value, res[cookieIndex].Value)
			}
		}

		return res, buf.Bytes()
	}
	for {
		if f, err := framer.ReadFrame(); err != nil {
			break
		} else {
			continuationFrame := f.(*http2.ContinuationFrame) // guaranteed by checkFrameOrder
			buf.Write(continuationFrame.HeaderBlockFragment())
			_, err = decoder.Write(continuationFrame.HeaderBlockFragment())
			if err != nil {
				log.Printf("Error decode %v", err)
			}
			if continuationFrame.HeadersEnded() {
				break
			}
		}
	}

	if hostIndex > 0 || pathIndex > 0 {
		res[pathIndex].Value = HostPathForceSafeSearch(res[hostIndex].Value, res[pathIndex].Value)
		if cookieIndex > 0 {
			res[cookieIndex].Value = CookiePatchSafeSearch(res[hostIndex].Value, res[cookieIndex].Value)
		}
	}

	return res, buf.Bytes()
}

func writeFinalData(framer *http2.Framer, streamId uint32, data *bytes.Buffer, chunkSize int) {
	dataToSend := data.Bytes()
	for i := 0; i < len(dataToSend); i += chunkSize {
		end := i + chunkSize
		dataEnded := false
		if end >= len(dataToSend) {
			end = len(dataToSend)
			dataEnded = true
		}

		framer.WriteData(streamId, dataEnded, dataToSend[i:end])
	}
}

func writeHeaders(framer *http2.Framer, param *http2.HeadersFrameParam, decoder *hpack.Decoder) {
	dataToSend := param.BlockFragment
	chunkSize := 15 * 1024
	for i := 0; i < len(dataToSend); i += chunkSize {
		end := i + chunkSize
		headesEnd := false
		if end >= len(dataToSend) {
			end = len(dataToSend)
			headesEnd = true
		}

		if i == 0 {
			/*	decoder.SetEmitEnabled(true)
				decoder.SetMaxStringLength(16 << 20)
				decoder.SetEmitFunc(func(hf hpack.HeaderField) {
					if len(hf.Name) > 0 {
						log.Printf("Writing header id:%d, %s:%s", param.StreamID, hf.Name, hf.Value)
					}
				})
				defer decoder.SetEmitFunc(func(hf hpack.HeaderField) {})
				defer decoder.Close()

				decoder.Write(dataToSend[i:end])*/

			framer.WriteHeaders(http2.HeadersFrameParam{
				StreamID:      param.StreamID,
				BlockFragment: dataToSend[i:end],
				EndStream:     headesEnd && param.EndStream,
				EndHeaders:    headesEnd,
				PadLength:     0,
				Priority:      param.Priority,
			})
		} else {
			framer.WriteContinuation(param.StreamID, headesEnd, dataToSend[i:end])
		}
	}
}

func makeHttpRequest(body []byte, header []hpack.HeaderField) *http.Request {
	req := http.Request{}
	req.Proto = "http/2"
	req.ProtoMajor = 2
	req.ProtoMinor = 0

	req.Header = http.Header{}
	scheme := "https"
	authority := ""
	path := ""
	for _, v := range header {
		if !strings.HasPrefix(v.Name, ":") {
			req.Header.Add(v.Name, v.Value)
		} else if v.Name == ":scheme" {
			scheme = v.Value
		} else if v.Name == ":authority" {
			authority = v.Value
		} else if v.Name == ":path" {
			path = v.Value
		} else if v.Name == ":method" {
			req.Method = v.Value
		}
	}

	req.RequestURI = scheme + "://" + authority + path
	req.URL, _ = url.ParseRequestURI(req.RequestURI)
	req.Host = req.URL.Host

	if len(body) == 0 {
		req.Body = http.NoBody
	} else {
		req.Body = ioutil.NopCloser(bytes.NewReader(body))
		req.ContentLength = int64(len(body))
	}
	return &req
}

func makeHttpResponse(body []byte, header []hpack.HeaderField) *http.Response {
	resp := http.Response{}

	resp.Proto = "http/2"
	resp.ProtoMajor = 2
	resp.ProtoMinor = 0
	resp.Header = http.Header{}
	for _, v := range header {
		if !strings.HasPrefix(v.Name, ":") {
			resp.Header.Add(v.Name, v.Value)
		} else if v.Name == ":status" {
			resp.Status = v.Value
			resp.StatusCode, _ = strconv.Atoi(v.Value)
		}
	}
	if len(body) == 0 {
		resp.Body = http.NoBody
		resp.ContentLength = 0
	} else {
		resp.Body = ioutil.NopCloser(bytes.NewReader(body))
		resp.ContentLength = int64(len(body))
	}
	return &resp
}

func putResponseBody(bodyParts [][]byte, resp *http.Response) {
	if len(bodyParts) == 0 {
		resp.Body = http.NoBody
	} else {
		body := make([]byte, 0)
		for _, b := range bodyParts {
			body = append(body, b...)
		}
		resp.Body = ioutil.NopCloser(bytes.NewReader(body))
		resp.ContentLength = int64(len(body))
	}
}

func encodeHeaderFields(fields []hpack.HeaderField) []byte {
	buf := new(bytes.Buffer)
	encoder := hpack.NewEncoder(buf)
	encoder.SetMaxDynamicTableSizeLimit(65536)
	buf.Reset()

	for i := 0; i < len(fields); i++ {
		encoder.WriteField(fields[i])
	}
	return buf.Bytes()
}

func encodeHeaders(resp *http.Response) []byte {
	buf := new(bytes.Buffer)
	encoder := hpack.NewEncoder(buf)
	//	encoder.SetMaxDynamicTableSize(65536)
	buf.Reset()

	writeHeader(encoder, ":status", strconv.Itoa(resp.StatusCode))
	writeHeader(encoder, "content-length", strconv.FormatInt(resp.ContentLength, 10))
	for k, vv := range resp.Header {
		lowKey := strings.ToLower(k)
		for _, v := range vv {
			writeHeader(encoder, lowKey, v)
		}
	}
	return buf.Bytes()
}

func writeHeader(encoder *hpack.Encoder, name, value string) {
	encoder.WriteField(hpack.HeaderField{Name: name, Value: value})
}
