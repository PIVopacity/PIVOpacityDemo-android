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

import android.app.Activity;
import android.app.AlertDialog;
import android.text.method.ScrollingMovementMethod;
import android.util.Log;
import android.view.Gravity;
import android.view.View;
import android.widget.TextView;

/**
 * A singleton that provides for standard Android logging
 * and for logging to the device screen.
 */
public class Logger
{
	private Activity activity;
	private TextView logText;

	/**
	 * Construct an instance.
	 * @param activity the activity for which we are logging
	 * @param logText the TextView to use for displaying messages on the device screen
	 */
	public Logger(Activity activity, TextView logText)
	{
		this.activity = activity;
		this.logText = logText;
		logText.setMovementMethod(new ScrollingMovementMethod());
		logText.setGravity(Gravity.BOTTOM);
	}

	/**
	 * Display an alert in a non-modal pop-up dialog on the device.
	 */
	public void alert(final String alert, final String title)
	{
		activity.runOnUiThread(new Runnable()
		{
			@Override
			public void run()
			{
				AlertDialog.Builder builder = new AlertDialog.Builder(activity);
				if (null != title)
				{
					builder.setTitle(title);
				}
				builder.setMessage(alert);
				builder.setNeutralButton("OK", null);
				builder.create().show();
			}
		});
	}

	private void displayAppend(final String msg)
	{
		activity.runOnUiThread(new Runnable()
		{
			@Override
			public void run()
			{
				logText.append(msg + "\n");
			}
		});
	}

	private void displaySet(String msg)
	{
		final String finalMsg = msg + "\n";
		activity.runOnUiThread(new Runnable()
		{
			@Override
			public void run()
			{
				logText.setText(finalMsg);
			}
		});
	}

	/**
	 * Clears the display on the device.
	 */
	public void clear()
	{
		displaySet("");
	}

	/**
	 * Log a debug message.
	 */
	public void debug(String tag, String msg)
	{
		Log.d(tag, msg);
	}

	/**
	 * Log an error message.
	 */
	public void error(String tag, String msg)
	{
		Log.e(tag, msg);
		displayAppend(msg);
	}

	/**
	 * Log an error message with a Throwable.
	 */
	public void error(String tag, String msg, Throwable tr)
	{
		Log.e(tag, msg, tr);
		displayAppend(msg + ": " + tr.getMessage());
	}

	/**
	 * Log an info message.
	 */
	public void info(String tag, final String msg)
	{
		Log.i(tag, msg);
		displayAppend(msg);
	}

	/**
	 * Log a newline - only applies to the device screen.
	 */
	public void newLine()
	{
		displayAppend("");
	}

	/**
	 * Log a warning message.
	 */
	public void warn(String tag, final String msg)
	{
		Log.w(tag, msg);
		displayAppend(msg);
	}

	/**
	 * Log a warning message with a Throwable.
	 */
	public void warn(String tag, final String msg, final Throwable tr)
	{
		Log.w(tag, msg, tr);
		displayAppend(msg + ": " + tr.getMessage());
	}
}
