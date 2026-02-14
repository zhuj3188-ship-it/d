package com.env.detector;

import android.app.AlertDialog;
import android.graphics.Color;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.View;
import android.widget.ProgressBar;
import android.widget.TextView;
import androidx.appcompat.app.AppCompatActivity;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Executors;

public class MainActivity extends AppCompatActivity {
    private TextView btnScan, tvStatus, tvProgress;
    private ProgressBar progressBar;
    private RecyclerView rvResults;
    private ResultAdapter adapter;
    private List<DetectionCategory> results = new ArrayList<>();
    private boolean disclaimerShown = false;

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        setContentView(R.layout.activity_main);

        btnScan = findViewById(R.id.btnScan);
        tvStatus = findViewById(R.id.tvStatus);
        tvProgress = findViewById(R.id.tvProgress);
        progressBar = findViewById(R.id.progressBar);
        rvResults = findViewById(R.id.rvResults);

        rvResults.setLayoutManager(new LinearLayoutManager(this));
        adapter = new ResultAdapter(this, results);
        rvResults.setAdapter(adapter);

        btnScan.setOnClickListener(v -> {
            if (!disclaimerShown) {
                new AlertDialog.Builder(this)
                    .setTitle(R.string.disclaimer_title)
                    .setMessage(R.string.disclaimer_msg)
                    .setPositiveButton(R.string.ok, (d, w) -> { disclaimerShown = true; startScan(); })
                    .setCancelable(false).show();
            } else {
                startScan();
            }
        });
    }

    private void startScan() {
        btnScan.setEnabled(false);
        btnScan.setText(R.string.scanning);
        progressBar.setVisibility(View.VISIBLE);
        tvProgress.setVisibility(View.VISIBLE);
        progressBar.setProgress(0);
        results.clear();
        adapter.notifyDataSetChanged();

        Handler h = new Handler(Looper.getMainLooper());
        Executors.newSingleThreadExecutor().execute(() -> {
            for (int i = 0; i <= 90; i += 10) {
                int p = i;
                h.post(() -> { progressBar.setProgress(p); tvProgress.setText(p + "%"); });
                try { Thread.sleep(80); } catch (Exception e) {}
            }

            List<DetectionCategory> cats = new DetectionEngine(this).runAll();

            h.post(() -> {
                progressBar.setProgress(100);
                tvProgress.setText("100%");
                results.clear();
                results.addAll(cats);
                adapter.notifyDataSetChanged();

                int risks = 0;
                for (DetectionCategory c : cats) risks += c.riskCount();

                if (risks == 0) {
                    tvStatus.setText(R.string.no_issues);
                    tvStatus.setTextColor(Color.parseColor("#4CAF50"));
                } else {
                    tvStatus.setText(String.format(getString(R.string.issues_found), risks));
                    tvStatus.setTextColor(Color.parseColor("#F44336"));
                    new AlertDialog.Builder(MainActivity.this)
                        .setTitle("检测结果")
                        .setMessage("发现 " + risks + " 个安全问题")
                        .setPositiveButton(R.string.ok, null).show();
                }

                btnScan.setEnabled(true);
                btnScan.setText(R.string.scan);
                h.postDelayed(() -> {
                    progressBar.setVisibility(View.GONE);
                    tvProgress.setVisibility(View.GONE);
                }, 1000);
            });
        });
    }
}
