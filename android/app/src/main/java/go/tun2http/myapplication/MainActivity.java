package go.tun2http.myapplication;

import android.Manifest;
import android.annotation.TargetApi;
import android.app.Activity;
import android.app.ProgressDialog;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.net.VpnService;
import android.os.Build;
import android.os.Bundle;
import android.os.Environment;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import gotun2socks.AdBlockMatcher;
import gotun2socks.Gotun2socks;

public class MainActivity extends Activity {
    private static final int REQUEST_CODE_CHOOSE_FILE_RULES = 0;
    private static final int REQUEST_CODE_START_VPN = 2;
    Button start;
    Button stop;
    Button loadRules;
    Button enableBypass;
    Button disableBypass;
    Button loadFromFile;
    Button saveToFile;
    Button prof;
    TextView info;

    AdBlockMatcher adBlockMatcher;

    ProgressDialog progressDialog;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        start = findViewById(R.id.start);
        stop = findViewById(R.id.stop);
        loadRules = findViewById(R.id.load_rules);
        info = findViewById(R.id.info);
        prof = findViewById(R.id.prof);
        loadFromFile = findViewById(R.id.load_from_file);
        enableBypass = findViewById(R.id.enable_bypass);
        disableBypass = findViewById(R.id.disable_bypass);
        saveToFile = findViewById(R.id.save_to_file);

        start.setOnClickListener(v -> startVpn());
        stop.setOnClickListener(v -> stopVpn());
        loadRules.setOnClickListener(v -> loadRules(REQUEST_CODE_CHOOSE_FILE_RULES));
        loadFromFile.setOnClickListener(this::loadFromFile);
        saveToFile.setOnClickListener(this::saveToFile);

        enableBypass.setOnClickListener(this::enableBypass);
        disableBypass.setOnClickListener(this::disableBypass);

        prof.setOnClickListener(v -> Gotun2socks.prof());


        start.setEnabled(true);
        stop.setEnabled(false);

    }

    private void enableBypass(View view) {
        if(adBlockMatcher == null) {
            return;
        }
        adBlockMatcher.enableBypass();
    }

    private void disableBypass(View view) {
        if(adBlockMatcher == null) {
            return;
        }

        adBlockMatcher.disaleBypass();
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
        adBlockMatcher = null;
    }

    private void startVpn() {
        if(!checkPermissions()) {
            return;
        }

        String dir =  Environment.getExternalStorageDirectory().getAbsolutePath();
        String certPath = dir + "/self_cert.pem";
        String keyPath = dir + "/self_cert.key";

        File certFile = new File(certPath);
        File keyFile = new File(keyPath);
        if(!certFile.exists() || !keyFile.exists()) {
            Gotun2socks.generateCerts(certPath, keyPath);
        }
        Gotun2socks.loadAndSetCa(certPath, keyPath);

        initMatcher();
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
    }

    @TargetApi(Build.VERSION_CODES.M)
    private boolean checkPermissions() {
        if(Build.VERSION.SDK_INT > Build.VERSION_CODES.M) {
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
        } else if (requestCode == REQUEST_CODE_CHOOSE_FILE_RULES) {
            Uri uri = data.getData();
            try {
                appendRulesToMatcher(uri, R.string.feeding_rules);
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    private void initMatcher() {
        if (adBlockMatcher != null) {
            return;
        }

        adBlockMatcher = Gotun2socks.createMatcher();
    }

    private void saveToFile(View view) {
        if (adBlockMatcher == null) {
            return;
        }

        new Thread(() -> {
            long t = System.currentTimeMillis();
            String filePath = getExternalFilesDir(null).getAbsolutePath() + "/rules.bin";
            adBlockMatcher.saveToFile(filePath);
            Log.d("Prof", "dump file size: " + new File(filePath).length());
            float dt = (System.currentTimeMillis() - t) / 1000.0f;
            Log.d("Prof", "Adblock matcher dumped " + dt);
        }).start();
    }

    private void loadFromFile(View view) {
        new Thread(() -> {
            String path = getExternalFilesDir(null).getAbsolutePath() + "/rules.bin";
            if (new File(path).exists()) {
                long t = System.currentTimeMillis();
                adBlockMatcher = Gotun2socks.loadMatcherFromFile(path);
                adBlockMatcher.build();
                float dt = (System.currentTimeMillis() - t) / 1000.0f;
                Log.d("Prof", "Adblock matcher loaded from dump " + dt);
                runOnUiThread(this::updateDbInfo);
            }
        }).start();
    }

    private void appendRulesToMatcher(Uri uri, int caption) throws IOException {
        final InputStream inputStream = getContentResolver().openInputStream(uri);
        if (inputStream == null) {
            return;
        }

        initMatcher();

        progressDialog = new ProgressDialog(this);
        progressDialog.setTitle(caption);
        progressDialog.setIndeterminate(true);
        progressDialog.show();
        new Thread(() -> {
            try {
                float dt = 0;
                String newPath = getExternalFilesDir(null).getAbsolutePath() + "/rules.zip";
                File targetFile = new File(newPath);
                OutputStream outStream = new FileOutputStream(targetFile);
                byte[] buffer = new byte[1024];
                int len;
                while ((len = inputStream.read(buffer)) != -1) {
                    outStream.write(buffer, 0, len);
                }
                outStream.close();

                inputStream.close();

                long t = System.currentTimeMillis();
                adBlockMatcher.parseRulesZipArchive(newPath);
                //   final int n = i;
                //    MainActivity.this.runOnUiThread(() -> progressDialog.setMessage(n + " items.Committing changes.."));

                progressDialog.dismiss();

                adBlockMatcher.build();
                MainActivity.this.runOnUiThread(this::updateDbInfo);

                dt += (System.currentTimeMillis() - t) / 1000.0f;
                Log.d("Prof", "AdBlock Dt time: " + dt + "s");
            } catch (Exception e) {
                e.printStackTrace();
            }
        }).start();
    }

    private void updateDbInfo() {
        info.setText("Rules loaded " + adBlockMatcher.rulesCount() + " Phrases loaded " + adBlockMatcher.phrasesCount());
    }
}
