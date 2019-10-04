package go.tun2http.myapplication;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.PackageManager;
import android.net.ConnectivityManager;
import android.net.VpnService;
import android.os.Build;
import android.os.Environment;
import android.os.IBinder;
import android.os.ParcelFileDescriptor;
import android.text.TextUtils;
import android.util.Base64;

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
            setupProxyServers();
            Builder builder = setupBuilder();
            parcelFileDescriptor = builder.establish();

            String dir = Environment.getExternalStorageDirectory().getAbsolutePath();
            Gotun2socks.run(parcelFileDescriptor.getFd(), MAX_CPUS, true, dir + "/self_cert.pem", dir + "/self_cert.key");
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
        builder.addAddress("10.0.0.2", 32);
        builder.addRoute("0.0.0.0", 0);
        builder.addRoute("0:0:0:0:0:0:0:0", 0);

        /*String dnsServer = "8.8.8.8";
        builder.addDnsServer(dnsServer);
        Gotun2socks.setDnsServer(dnsServer);*/

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            try {
                builder.addDisallowedApplication(getPackageName());
            } catch (PackageManager.NameNotFoundException e) {
                e.printStackTrace();
            }
        }

        builder.setMtu(15000);

        return builder;
    }

    private void setupProxyServers() {
        String header = Base64.encodeToString(("test@test.com" + ":" + "1").getBytes(), Base64.NO_WRAP);
//        Gotun2socks.setDefaultProxy("45.79.132.164:19752", PROXY_TYPE_HTTP, header, "cloudveilsocks", "cloudveilsocks");

       Gotun2socks.setDefaultProxy("127.0.0.1:23500", PROXY_TYPE_HTTP, header, "cloudveilsocks", "cloudveilsocks");
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
