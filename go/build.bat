SET ANDROID_NDK_HOME=%APPDATA%\..\Local\Android\Sdk\ndk\21.4.7075529
SET JAVA_HOME=c:\Program Files\Android\Android Studio\jbr\bin
set PATH=%PATH%;c:\Program Files\Android\Android Studio\jbr\bin

gomobile bind -o tun2http.aar -v -ldflags="-s -w" -target=android github.com/dkwiebe/gotun2socks 
