package go.tun2http.myapplication;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.net.ConnectivityManager;
import android.net.VpnService;
import android.os.Build;
import android.os.Environment;
import android.os.IBinder;
import android.os.ParcelFileDescriptor;
import android.text.TextUtils;
import android.util.Base64;
import android.util.Log;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.Inet6Address;
import java.net.InetAddress;

import javax.annotation.Nonnull;

import gotun2socks.Gotun2socks;


public class Tun2HttpVpnService extends VpnService {
    private static final int MAX_CPUS = 2;
    private static final int PROXY_TYPE_SOCKS = 1;
    private static final int PROXY_TYPE_HTTP = 2;
    private static final String ACTION_START = "start";
    private static final String ACTION_STOP = "stop";
    private static final String ACTION_RESTART_IF_RUNNING = "restart_if_running";
    private static final String EXTRA_APP_PACKAGE_NAME = "app_package_name";

    private ParcelFileDescriptor parcelFileDescriptor = null;
    private ConnectivityChangeReceiver connectivityChangeReceiver;

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }


    public boolean isRunning() {
        return parcelFileDescriptor != null;
    }

    private void start() {
        if(connectivityChangeReceiver == null) {
            connectivityChangeReceiver = new ConnectivityChangeReceiver((ConnectivityManager) getSystemService(Context.CONNECTIVITY_SERVICE));
        }
        if (parcelFileDescriptor == null) {
            Builder builder = setupBuilder();
            setupProxyServers(builder);
            parcelFileDescriptor = builder.establish();

            String dir = Environment.getExternalStorageDirectory().getAbsolutePath();
            Gotun2socks.run(parcelFileDescriptor.getFd(), MAX_CPUS);
        }

        this.registerReceiver(connectivityChangeReceiver, new IntentFilter(android.net.ConnectivityManager.CONNECTIVITY_ACTION));
    }

    private void stop(boolean removeNotification) {
        try {
            this.unregisterReceiver(connectivityChangeReceiver);
        } catch(Exception e) {

        }
        try {
            if (parcelFileDescriptor != null) {
                parcelFileDescriptor.close();
                parcelFileDescriptor = null;
                Gotun2socks.stop();
            }
        } catch (Throwable ex) {
        }
        if(removeNotification) {
            stopForeground(true);
        }
    }
    private void stop() {
        stop(true);
    }


    @Override
    public void onRevoke() {
        stop();
        parcelFileDescriptor = null;
        super.onRevoke();
    }


    private Builder setupBuilder() {
        // Build VPN service
        Builder builder = new Builder();
        builder.setSession(getString(R.string.app_name));

        // VPN address
     //   builder.addAddress("10.0.0.2", 32);
        builder.addAddress("fc00::1", 7);
        builder.addRoute("0.0.0.0", 0);
        builder.addRoute("0:0:0:0:0:0:0:0", 0);

 		//String dnsServer = "2001:4860:4860::8888";
      //  builder.addDnsServer(dnsServer);
    //    Gotun2socks.setDnsServer(dnsServer, 53);
    /*    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            try {
                builder.addDisallowedApplication(getPackageName());
            } catch (PackageManager.NameNotFoundException e) {
                e.printStackTrace();
            }
        }
*/
        builder.setMtu(10240);

        return builder;
    }

    public ApplicationInfo getApplicationInfo(String packageName) {
        if (packageName == null)
            return null;
        try {
            return getPackageManager().getApplicationInfo(packageName, PackageManager.GET_META_DATA);
        } catch (PackageManager.NameNotFoundException e) {
            return null;
        }
    }

    private void setupProxyServers(@Nonnull Builder builder) {
        String header = Base64.encodeToString(("test@test.com" + ":" + "1").getBytes(), Base64.NO_WRAP);
//        Gotun2socks.setDefaultProxy("45.79.132.164:19752", PROXY_TYPE_HTTP, header, "cloudveilsocks", "cloudveilsocks");
        Gotun2socks.setDefaultProxy(":", PROXY_TYPE_HTTP, header, "cloudveilsocks", "cloudveilsocks");

        ApplicationInfo applicationInfo = getApplicationInfo("com.android.chrome");
        if(applicationInfo == null) {
            return;
        }
        Gotun2socks.addProxyServer(applicationInfo.uid, "proxy_us_nj_1.cloudveil.org:8085", PROXY_TYPE_HTTP, "","cloudveilsocks", "cloudveilsocks");
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            try {
                builder.addAllowedApplication("com.android.chrome");
            } catch (PackageManager.NameNotFoundException e) {
                e.printStackTrace();
            }
        }
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        // Handle service restart
        if (intent == null) {
            return START_STICKY;
        }

        if (ACTION_START.equals(intent.getAction())) {
            start();
        }
        if (ACTION_STOP.equals(intent.getAction())) {
            stop();
        } else if(ACTION_RESTART_IF_RUNNING.equals(intent.getAction())) {
            restartIfRunning();
        }
        return START_STICKY;
    }

    private void restartIfRunning() {
        if(parcelFileDescriptor == null) {
            return;
        }
        stop(false);
        start();
    }

    @Override
    public void onDestroy() {
        stop();
        super.onDestroy();
    }

    public static void start(Context context) {
        Intent intent = new Intent(context, Tun2HttpVpnService.class);
        intent.setAction(ACTION_START);
        intent.putExtra(EXTRA_APP_PACKAGE_NAME, context.getPackageName());

        context.startService(intent);
    }


    public static void stop(Context context) {
        Intent intent = new Intent(context, Tun2HttpVpnService.class);
        intent.setAction(ACTION_STOP);
        context.startService(intent);
    }


    public static void restartIfRunning(Context context) {
        Intent intent = new Intent(context, Tun2HttpVpnService.class);
        intent.setAction(ACTION_RESTART_IF_RUNNING);
        context.startService(intent);
    }
}
