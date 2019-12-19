package io.github.margular;

import android.os.AsyncTask;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;

class AsyncRequest extends AsyncTask<Void, Void, Void> {

    @Override
    protected void onPreExecute() {
        //display progress dialog.

    }

    @Override
    protected Void doInBackground(Void... params) {
        try {
            URL url = new URL("https://www.baidu.com/");

            HttpURLConnection con = (HttpURLConnection) url.openConnection();

            System.out.println(con.getResponseCode() + " " + con.getResponseMessage() + "\n");
        } catch (IOException e) {
            e.printStackTrace();
        }

        return null;
    }

    @Override
    protected void onPostExecute(Void result) {
        // dismiss progress dialog and update ui
    }
}
