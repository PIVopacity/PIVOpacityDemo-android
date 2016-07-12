/*
MIT License

Copyright (c) 2016 United States Government

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

Written by Christopher Williams, Ph.D. (cwilliams@exponent.com) & John Koehring (jkoehring@exponent.com)
*/

package com.exponent.androidopacitydemo;

import android.Manifest;
import android.app.Activity;
import android.content.pm.PackageManager;
import android.nfc.NfcAdapter;
import android.os.Bundle;
import android.support.v4.app.ActivityCompat;
import android.support.v7.app.AppCompatActivity;
import android.support.v7.widget.Toolbar;
import android.view.Menu;
import android.view.MenuItem;
import android.widget.TextView;

import com.exponent.opacity.Opacity;

/**
 * The main activity for this application.
 */
public class MainActivity extends AppCompatActivity
{
	public static Logger logger;

	private CacReader cacReader;

	private final static String TAG = "MainActivity";

	private final static int NFC_READER_FLAGS = NfcAdapter.FLAG_READER_NFC_A | NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK;

	// Storage Permissions
	private static final int REQUEST_EXTERNAL_STORAGE = 1;
	private static String[] PERMISSIONS_STORAGE = {
			Manifest.permission.READ_EXTERNAL_STORAGE,
			Manifest.permission.WRITE_EXTERNAL_STORAGE
	};

	public static void verifyStoragePermissions(Activity activity)
	{
		// Check if we have write permission
		int permission = ActivityCompat.checkSelfPermission(activity, Manifest.permission.WRITE_EXTERNAL_STORAGE);

		if (permission != PackageManager.PERMISSION_GRANTED)
		{
			// We don't have permission so prompt the user
			ActivityCompat.requestPermissions(
					activity,
					PERMISSIONS_STORAGE,
					REQUEST_EXTERNAL_STORAGE
			);
		}
	}

	@Override
	protected void onCreate(Bundle savedInstanceState)
	{
		super.onCreate(savedInstanceState);
		setContentView(R.layout.activity_main);
		Toolbar toolbar = (Toolbar) findViewById(R.id.toolbar);
		setSupportActionBar(toolbar);

		TextView logText = (TextView) findViewById(R.id.logText);
		logger = new Logger(this, logText);
		Opacity.logger = logger;

		verifyStoragePermissions(this);

		// Create the CAC reader and turn on the NFC reader:
		cacReader = new CacReader(this, logger);
		enableNfcReaderMode();
	}

	private void enableNfcReaderMode()
	{
		logger.debug(TAG, "Enabling reader mode");
		NfcAdapter nfc = NfcAdapter.getDefaultAdapter(this);
		if (nfc != null)
		{
			// Turn on the NFC reader, registering our CacReader as the callback:
			nfc.enableReaderMode(this, cacReader, NFC_READER_FLAGS, null);
		}
	}

	private void disableNfcReaderMode()
	{
		logger.debug(TAG, "Disabling reader mode");
		NfcAdapter nfc = NfcAdapter.getDefaultAdapter(this);
		if (nfc != null)
		{
			nfc.disableReaderMode(this);
		}
	}

	@Override
	public boolean onCreateOptionsMenu(Menu menu)
	{
		// Inflate the menu; this adds items to the action bar if it is present.
		getMenuInflater().inflate(R.menu.menu_main, menu);
		return true;
	}

	@Override
	public boolean onOptionsItemSelected(MenuItem item)
	{
		// Handle action bar item clicks here. The action bar will
		// automatically handle clicks on the Home/Up button, so long
		// as you specify a parent activity in AndroidManifest.xml.
		int id = item.getItemId();

		//noinspection SimplifiableIfStatement
		if (id == R.id.action_settings)
		{
			return true;
		}

		return super.onOptionsItemSelected(item);
	}

	/**
	 * Called when the activity is paused.
	 */
	@Override
	public void onPause()
	{
		super.onPause();
		logger.debug(TAG, "Pause");
		disableNfcReaderMode();
	}

	/**
	 * Called when the activity is resumed.
	 */
	@Override
	public void onResume()
	{
		super.onResume();
		logger.debug(TAG, "Resume");
		enableNfcReaderMode();
	}
}
