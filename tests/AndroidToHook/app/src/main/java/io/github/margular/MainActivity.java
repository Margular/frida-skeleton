package io.github.margular;

import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.text.method.ScrollingMovementMethod;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;
import android.widget.Toast;

public class MainActivity extends AppCompatActivity implements View.OnClickListener {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        Button btnSpeak = findViewById(R.id.btnSpeak);
        btnSpeak.setOnClickListener(this);

        TextView txtHttp = findViewById(R.id.txtHttp);
        txtHttp.setMovementMethod(new ScrollingMovementMethod());
    }

    @Override
    public void onClick(View v) {
        switch (v.getId()) {
            case R.id.btnSpeak:
                Toast.makeText(getApplicationContext(), getBestLanguage("Python") + " is the best"
                        + " programming language of the world!", Toast.LENGTH_SHORT).show();
                new AsyncRequest().execute();
                break;
        }
    }

    private String getBestLanguage(String lang) {
        return lang;
    }
}
