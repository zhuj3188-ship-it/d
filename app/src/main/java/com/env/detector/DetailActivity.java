package com.env.detector;

import android.os.Bundle;
import android.widget.TextView;
import androidx.appcompat.app.AppCompatActivity;

public class DetailActivity extends AppCompatActivity {
    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        setContentView(R.layout.activity_detail);
        ((TextView) findViewById(R.id.tvDetailTitle)).setText(getIntent().getStringExtra("title"));
        ((TextView) findViewById(R.id.tvDetailContent)).setText(getIntent().getStringExtra("content"));
        findViewById(R.id.btnBack).setOnClickListener(v -> finish());
    }
}
