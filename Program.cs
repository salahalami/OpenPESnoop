/*
 * Created by SharpDevelop.
 * Date: 9/25/2015
 * Time: 5:10 AM
 * 
 * Copyright (C) 2015 Salah Alami. All Rights Reserved.
 * Contact: salahalami21@gmail.com
 * City: Casablanca, Morocco
 * 
 */
using System;

namespace OpenPESnoop
{
	class Program
	{
		public static void Main(string[] args)
		{
			PESnoop p = new PESnoop(@"C:\path\to\my\dll.exe");
			p.PrintDosHeader();
			p.PrintDataDirectory();
			//...
			
			Console.Write("Press any key to continue . . . ");
			Console.ReadKey(true);
		}
	}
}
