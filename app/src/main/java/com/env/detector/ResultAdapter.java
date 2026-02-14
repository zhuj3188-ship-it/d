package com.env.detector;

import android.content.Context;
import android.content.Intent;
import android.graphics.Color;
import android.graphics.drawable.GradientDrawable;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.recyclerview.widget.RecyclerView;
import java.util.List;

public class ResultAdapter extends RecyclerView.Adapter<ResultAdapter.VH> {
    private final List<DetectionCategory> cats;
    private final Context ctx;

    public ResultAdapter(Context ctx, List<DetectionCategory> cats) {
        this.ctx = ctx;
        this.cats = cats;
    }

    @NonNull @Override
    public VH onCreateViewHolder(@NonNull ViewGroup p, int t) {
        return new VH(LayoutInflater.from(p.getContext()).inflate(R.layout.item_category, p, false));
    }

    @Override
    public void onBindViewHolder(@NonNull VH h, int pos) {
        DetectionCategory cat = cats.get(pos);
        h.tvName.setText(cat.name);

        GradientDrawable dot = new GradientDrawable();
        dot.setShape(GradientDrawable.OVAL);
        dot.setColor(cat.hasRisk() ? Color.parseColor("#F44336") : Color.parseColor("#4CAF50"));
        h.statusDot.setBackground(dot);

        if (cat.hasRisk()) {
            h.tvStatus.setText(cat.riskCount() + " 项异常");
            h.tvStatus.setTextColor(Color.parseColor("#F44336"));
        } else {
            h.tvStatus.setText("正常");
            h.tvStatus.setTextColor(Color.parseColor("#4CAF50"));
        }

        h.expandable.removeAllViews();
        h.expandable.setVisibility(cat.expanded ? View.VISIBLE : View.GONE);

        if (cat.expanded) {
            LayoutInflater inf = LayoutInflater.from(ctx);
            for (DetectionItem item : cat.items) {
                View iv = inf.inflate(R.layout.item_detection, h.expandable, false);
                TextView tvI = iv.findViewById(R.id.tvIcon);
                TextView tvN = iv.findViewById(R.id.tvItemName);
                TextView tvV = iv.findViewById(R.id.tvItemValue);

                tvI.setText(item.isRisk ? "✗" : "✓");
                tvI.setTextColor(item.isRisk ? Color.parseColor("#F44336") : Color.parseColor("#4CAF50"));
                tvN.setText(item.name);
                tvV.setText(item.value);
                tvV.setTextColor(item.isRisk ? Color.parseColor("#F44336") : Color.parseColor("#4CAF50"));

                iv.setOnClickListener(v -> {
                    if (item.detail != null && !item.detail.isEmpty()) {
                        Intent intent = new Intent(ctx, DetailActivity.class);
                        intent.putExtra("title", item.name);
                        intent.putExtra("content", item.detail);
                        ctx.startActivity(intent);
                    }
                });
                h.expandable.addView(iv);
            }
        }

        h.header.setOnClickListener(v -> {
            cat.expanded = !cat.expanded;
            notifyItemChanged(pos);
        });
    }

    @Override public int getItemCount() { return cats.size(); }

    static class VH extends RecyclerView.ViewHolder {
        TextView tvName, tvStatus;
        View statusDot;
        LinearLayout expandable, header;
        VH(View v) {
            super(v);
            tvName = v.findViewById(R.id.tvCategoryName);
            tvStatus = v.findViewById(R.id.tvCategoryStatus);
            statusDot = v.findViewById(R.id.statusDot);
            expandable = v.findViewById(R.id.expandableLayout);
            header = v.findViewById(R.id.categoryHeader);
        }
    }
}
