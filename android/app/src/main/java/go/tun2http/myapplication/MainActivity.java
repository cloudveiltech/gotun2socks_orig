package go.tun2http.myapplication;

import android.Manifest;
import android.annotation.TargetApi;
import android.app.Activity;
import android.app.ProgressDialog;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.net.ConnectivityManager;
import android.net.LinkProperties;
import android.net.Network;
import android.net.NetworkInfo;
import android.net.Uri;
import android.net.VpnService;
import android.os.Build;
import android.os.Bundle;
import android.os.Environment;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;

import gotun2socks.AdBlockMatcher;
import gotun2socks.Gotun2socks;

public class MainActivity extends Activity {
    private static final int REQUEST_CODE_CHOOSE_FILE_RULES = 0;
    private static final int REQUEST_CODE_START_VPN = 2;
    Button start;
    Button stop;
    Button saveToFile;
    Button prof;
    TextView info;
    ProgressDialog progressDialog;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        start = findViewById(R.id.start);
        stop = findViewById(R.id.stop);
        info = findViewById(R.id.info);
        prof = findViewById(R.id.prof);

        start.setOnClickListener(v -> startVpn());
        stop.setOnClickListener(v -> stopVpn());
        prof.setOnClickListener(v -> Gotun2socks.prof());

        start.setEnabled(true);
        stop.setEnabled(false);

    }

    private void printDnsServers() {
        if(Build.VERSION.SDK_INT < Build.VERSION_CODES.LOLLIPOP) {
            return;
        }

        ConnectivityManager connectivityManager = (ConnectivityManager) getSystemService(CONNECTIVITY_SERVICE);
        if(connectivityManager == null) {
            return;
        }

        for (Network network : connectivityManager.getAllNetworks()) {
            NetworkInfo networkInfo = connectivityManager.getNetworkInfo(network);
            if (networkInfo != null) {
                LinkProperties linkProperties = connectivityManager.getLinkProperties(network);
                if (linkProperties != null) {
                    Log.d("LockerDnsInfo", "iface = " + linkProperties.getInterfaceName());
                    Log.d("LockerDnsInfo", "dns = " + linkProperties.getDnsServers());
                }
            }
        }
    }


    private void loadRules(int requestId) {
        Intent chooseFile;
        Intent intent;
        chooseFile = new Intent(Intent.ACTION_OPEN_DOCUMENT);
        chooseFile.addCategory(Intent.CATEGORY_OPENABLE);
        chooseFile.setType("application/zip");
        intent = Intent.createChooser(chooseFile, "Choose a file");
        startActivityForResult(intent, requestId);
    }


    @Override
    protected void onPause() {
        super.onPause();
    }

    private void stopVpn() {
        start.setEnabled(true);
        stop.setEnabled(false);

        Tun2HttpVpnService.stop(this);
    }

    private void startVpn() {
        if (!checkPermissions()) {
            return;
        }

        Intent i = VpnService.prepare(this);
        if (i != null) {
            startActivityForResult(i, REQUEST_CODE_START_VPN);
        } else {
            onActivityResult(REQUEST_CODE_START_VPN, Activity.RESULT_OK, null);
        }
    }

    @Override
    protected void onResume() {
        super.onResume();
        checkPermissions();
        printDnsServers();
    }

    @TargetApi(Build.VERSION_CODES.M)
    private boolean checkPermissions() {
        if (Build.VERSION.SDK_INT > Build.VERSION_CODES.M) {
            if (checkSelfPermission(Manifest.permission.WRITE_EXTERNAL_STORAGE) != PackageManager.PERMISSION_GRANTED) {
                requestPermissions(new String[]{Manifest.permission.WRITE_EXTERNAL_STORAGE}, 1);
                return false;
            }
        }
        return true;
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);

        if (resultCode != Activity.RESULT_OK) {
            return;
        }

        if (requestCode == REQUEST_CODE_START_VPN) {
            start.setEnabled(false);
            stop.setEnabled(true);
            Tun2HttpVpnService.start(this);
        }
    }
}
