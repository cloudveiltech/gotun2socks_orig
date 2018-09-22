# gotun2socks mobile
This is a fork of gotun2socks project adopted for Android platform.

# Building
1. Install go.
1. Install gomobile.
1. Put go sources sources into your %GoPath%/src/github.com/dkwiebe/gotun2socks
1. Open android project.
1. Adjust tun2http/build.gradle with your pathes
1. Build.

# Features/limitations
1. Support http with basic auth and socks5 proxy with login-password auth
1. Different apps can be routed to different proxies using app UID.
UID can be obtained as
https://stackoverflow.com/questions/41869659/how-can-i-get-uid-of-some-other-app-whose-package-name-i-know-in-android
1. This implementation forwards to proxies only 80 and 443 http ports over TCP protocol
