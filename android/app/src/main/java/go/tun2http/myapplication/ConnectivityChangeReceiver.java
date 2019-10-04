package go.tun2http.myapplication;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import android.util.Log;


public class ConnectivityChangeReceiver extends BroadcastReceiver {
    NetworkInfo activeNetworkInfo;
    private ConnectivityManager connectivityManager;

    public ConnectivityChangeReceiver(ConnectivityManager connectivityManager) {
        activeNetworkInfo = connectivityManager.getActiveNetworkInfo();
        this.connectivityManager = connectivityManager;
    }

    @Override
    public void onReceive(Context context, Intent intent) {
        if (intent.getAction() == null || !intent.getAction().equalsIgnoreCase(ConnectivityManager.CONNECTIVITY_ACTION)) {
            return;
        }

        NetworkInfo currentActiveNetworkInfo = connectivityManager.getActiveNetworkInfo();
        if(currentActiveNetworkInfo == null) {
            return;
        }
        if(activeNetworkInfo == null || currentActiveNetworkInfo.getType() != activeNetworkInfo.getType()) {
            if(currentActiveNetworkInfo.getState() == NetworkInfo.State.CONNECTED) {
                activeNetworkInfo = currentActiveNetworkInfo;
                Log.d("ConnectivityRecvr", "Restarting VPN on changing connection");
                Tun2HttpVpnService.restartIfRunning(context);
            }
        }
    }
}
