package go.tun2http.myapplication;

import android.app.Activity;
import android.content.Intent;
import android.net.Uri;
import android.net.VpnService;
import android.os.Bundle;
import android.util.Log;
import android.widget.Button;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;
import gotun2socks.BoltDB;
import gotun2socks.Gotun2socks;

public class MainActivity extends Activity {
    private static final int REQUEST_CODE_CHOOSE_FILE = 1;
    private static final int REQUEST_CODE_START_VPN = 2;
    Button start;
    Button stop;
    Button load;

    BoltDB boltDB;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        start = findViewById(R.id.start);
        stop = findViewById(R.id.stop);
        load = findViewById(R.id.load);

        start.setOnClickListener(v -> startVpn());
        stop.setOnClickListener(v -> stopVpn());
        load.setOnClickListener(v -> loadDataIntoDb());


        start.setEnabled(true);
        stop.setEnabled(false);

    }

    private void loadDataIntoDb() {
        Intent chooseFile;
        Intent intent;
        chooseFile = new Intent(Intent.ACTION_OPEN_DOCUMENT);
        chooseFile.addCategory(Intent.CATEGORY_OPENABLE);
        chooseFile.setType("text/plain");
        intent = Intent.createChooser(chooseFile, "Choose a file");
        startActivityForResult(intent, REQUEST_CODE_CHOOSE_FILE);
    }


    @Override
    protected void onPause() {
        super.onPause();
    }

    private void stopVpn() {
        start.setEnabled(true);
        stop.setEnabled(false);

        Tun2HttpVpnService.stop(this);
        boltDB = null;
    }

    private void startVpn() {
        initDb();
        Intent i = VpnService.prepare(this);
        if (i != null) {
            startActivityForResult(i, 0);
        } else {
            onActivityResult(REQUEST_CODE_START_VPN, Activity.RESULT_OK, null);
        }
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
        } else if (requestCode == REQUEST_CODE_CHOOSE_FILE) {
            Uri uri = data.getData();
            try {
                initDb();
                appendFileToFilterDb(uri);
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    private void initDb() {
        if(boltDB != null) {
            return;
        }
        String path;
        if (android.os.Build.VERSION.SDK_INT >=android.os.Build.VERSION_CODES.LOLLIPOP){
            path = getNoBackupFilesDir().getAbsolutePath();
        } else{
            path = getFilesDir().getAbsolutePath();
        }
        boltDB = Gotun2socks.newBoltDB(path);
    }

    private void appendFileToFilterDb(Uri uri) throws IOException {
        InputStream inputStream = getContentResolver().openInputStream(uri);
        if(inputStream == null) {
            return;
        }
        BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));
        String line;
        boltDB.beginTransaction();
        while ((line = reader.readLine()) != null) {
            boltDB.addBlockedDomain(line, (byte)1);

            Log.d("Uri", line);
        }
        boltDB.commitTransaction();
        inputStream.close();
    }
}
