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
import android.app.Dialog;
import android.app.DialogFragment;
import android.content.DialogInterface;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.widget.TextView;

import java.util.concurrent.Semaphore;

/**
 * Dialog fragment for obtaining numeric input from the user.
 * The dialog is implemented as a modal dialog.
 */
public class GetNumericInputDialogFragment extends DialogFragment
{
	private String input;
	private final Semaphore dialogSemaphore = new Semaphore(0, true);

	public static GetNumericInputDialogFragment create(String title)
	{
		GetNumericInputDialogFragment frag = new GetNumericInputDialogFragment();
		Bundle args = new Bundle();
		args.putCharSequence("title", title);
		frag.setArguments(args);
		return frag;
	}

	@Override
	public Dialog onCreateDialog(Bundle savedInstanceState)
	{
		AlertDialog.Builder builder = new AlertDialog.Builder(getActivity());

		//noinspection ConstantConditions
		builder.setTitle(getArguments().get("title").toString());
		builder.setCancelable(false);
		LayoutInflater inflater = getActivity().getLayoutInflater();
		final View dialogLayout = inflater.inflate(R.layout.dialog_get_numeric_input, null);
		builder.setView(dialogLayout);
		builder.setPositiveButton("OK", new DialogInterface.OnClickListener()
		{
			@Override
			public void onClick(DialogInterface dialog, int id)
			{
				TextView tv = (TextView) dialogLayout.findViewById(R.id.numericPassword);
				input = tv.getText().toString();
				dialogSemaphore.release();
			}
		});

		Dialog dialog = builder.create();
		dialog.setCancelable(false);
		dialog.setCanceledOnTouchOutside(false);
		return dialog;
	}

	/**
	 * Displays the modal dialog and returns the characters entered by the user.
	 */
	public String showDialog(Activity activity)
	{
		show(activity.getFragmentManager(),"numericPassword");

		try
		{
			dialogSemaphore.acquire();
		}
		catch (InterruptedException ex)
		{
			//ignore
		}

		return input;
	}

}