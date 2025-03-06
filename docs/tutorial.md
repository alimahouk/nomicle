# Get Started

[← Back to Main Documentation](../README.md)

## Table of Contents

1. [Windows](#windows)
2. [macOS](#macos)
3. [Linux](#linux)

## Windows

1. Download and install [Python 3](https://www.python.org/download/releases/3.0/) if you don't already have it installed. To find out:
   - Open the Start menu, type "cmd", and launch Command Prompt
   - In the Command Prompt window that appears, type "python". If you get an error, that means Python is either not installed or it hasn't been added to your PATH. Use your favourite web search engine to find out how to install Python 3 or how to add it to your PATH on Windows

2. Assuming Python 3 is now running in your Command Prompt window:
   - Make sure the displayed Python version number is of the form 3.x or 3.x.x (where "x" can be any number)
   - Install the [cryptography](https://cryptography.io/en/latest/) Python package by following the instructions on the project's website
   - You may then quit Python by typing "quit()" and pressing the Return key

3. [Download the Nomicle Complete Bundle for Windows](download.md#complete-bundles) and extract it into a folder called `Nomicle`. The final folder structure should look something like this:

   ```
   Nomicle/
   ├── PyNomicle/
   │   └── nomicle.py
   ├── fort.py
   ├── LICENSE
   ├── seed.py
   └── start.bat
   ```

4. You are now ready to run Nomicle on your computer:
   - Double-click `start.bat`. This will start the Fortifier and Seeder as background processes (i.e. you won't see a window appear)
   - *If you get a firewall alert, make sure to allow it through otherwise you won't be able to connect to the Nomicle network*
   - The next step is to set your Nomicle identifier

5. Set your Nomicle identifier:
   - Your Nomicle identifier can be any text that you think can be unique enough for others to find you (e.g. your favourite username or your email address)
   - The more unique your identifier, the more likely it is you will always own it and can start using it right away
   - Press the Windows key + R
   - In the Run window that appears, type: `%APPDATA%\NCLE`
   - In the window that appears, open the file named "id" in Notepad
   - Type in your chosen identifier, then save and close the Notepad window
   - You can change this identifier to something else whenever you want later on

6. That's it! You're now all set to run Nomicle-powered programs:
   - To get a feel for it, [download and run xTalk](https://github.com/alimahouk/xtalk), a Nomicle-powered messaging system
   - Nomicle runs in the background on your PC, and it is recommended that you leave it that way so long as your PC is running to allow the Fortifier to fortify your identity and help you maintain its ownership
   - To stop the Nomicle programs at any time, launch Task Manager, find the Fortifier and Seeder (they'll appear as two Python processes), and end their tasks

*Note: depending on whether someone else already owns a stronger version of your chosen identifier, you may not necessarily own the identity anytime soon after you start your own fortification of it. It may take a while depending on how much processing power the current owner has already invested in it as well as how long you leave the Fortifier running on your own PC.*

At the moment, there are two ways to find out whether you own the identity yet or not:

1. Try and have someone else use your nomicle in some way (e.g. sending you a message via xTalk and seeing if you successfully receive it)
2. [Run the Block Explorer](explorer.md), which displays whether or not you are the owner amongst the output it prints out

### Running on PC Startup

If you want Nomicle to automatically start up every time you restart your PC:

1. Open the Startup folder:
   - Press the Windows key + R
   - In the Run window that appears, type: `shell:startup`

2. Back in the Nomicle folder:
   - Right-click `start.bat` and choose "Create shortcut", which will then create a new shortcut file
   - Drag the shortcut file to the Startup folder in the other window

If at any time you decide you don't want Nomicle to start up with your PC, follow these steps to open the Startup folder and simply delete the shortcut to `start.bat`.

## macOS

1. Download and install [Python 3](https://www.python.org/download/releases/3.0/) if you don't already have it installed. To find out:
   - Use Spotlight search and type "terminal". Launch the Terminal app
   - Inside Terminal, type "python3". If you get an error, that means Python is probably not installed. Use your favourite web search engine to find out how to install Python 3 on macOS

2. Assuming Python 3 is now running in your Terminal window:
   - Make sure the displayed Python version number is of the form 3.x or 3.x.x (where "x" can be any number)
   - Install the [cryptography](https://cryptography.io/en/latest/) Python package by following the instructions on the project's website
   - You may then quit Python by typing "quit()" and pressing the Return key

3. [Download the Nomicle Complete Bundle for macOS/Linux](download.md#complete-bundles) and extract it into a directory called `Nomicle`. The final folder structure should look something like this:

   ```
   Nomicle/
   ├── PyNomicle/
   │   └── nomicle.py
   ├── fort.py
   ├── LICENSE
   ├── seed.py
   ├── start.sh
   └── stop.sh
   ```

4. You are now ready to run Nomicle on your Mac:
   - In the Terminal window, navigate to the Nomicle directory you extracted
   - An easy way to do this is to type "cd " (there's a space after the "cd") and then drag the directory from Finder and drop it over the cursor inside Terminal
   - Terminal should insert the path to the directory at the cursor. Press the Return key

5. Type the following (pressing the Return key after you enter each line; do not include the "$" character in what you type):

   ```bash
   sudo chmod u+x start.sh
   sudo chmod u+x stop.sh
   sudo chmod u+x fort.sh
   sudo chmod u+x seed.sh
   sudo ./start.sh
   ```

   - You will be prompted to enter the password you use to log into your Mac after you enter the first line because "sudo" is a command that uses administrator privileges
   - *If you get a firewall alert, make sure to allow it through otherwise you won't be able to connect to the Nomicle network*
   - The next step is to set your Nomicle identifier

6. Set your Nomicle identifier:
   - Your Nomicle identifier can be any text that you think can be unique enough for others to find you (e.g. your favourite username or your email address)
   - The more unique your identifier, the more likely it is you will always own it and can start using it right away
   - Press Shift + ⌘ + G
   - In the window that appears, type: `/usr/local/share/ncle`
   - In the Finder window that appears, open the file inside the `ncle` directory named "id" in TextEdit
   - Type in your chosen identifier, then save and quit TextEdit
   - You can change this identifier to something else whenever you want later on

7. That's it! You're now all set to run Nomicle-powered programs:
   - To get a feel for it, [download and run xTalk](https://github.com/alimahouk/xtalk), a Nomicle-powered messaging system
   - Nomicle runs in the background on your Mac, and it is recommended that you leave it that way so long as your Mac is running to allow the Fortifier to fortify your identity and help you maintain its ownership
   - To stop the Nomicle programs at any time, follow the steps above to navigate to the Nomicle directory and run the `stop.sh` script
   - Note that this will only work if you had started the programs using `start.sh`, otherwise you need to kill the Fortifier and Seeder processes yourself using Terminal or Activity Monitor

*Note: depending on whether someone else already owns a stronger version of your chosen identifier, you may not necessarily own the identity anytime soon after you start your own fortification of it. It may take a while depending on how much processing power the current owner has already invested in it as well as how long you leave the Fortifier running on your own Mac.*

At the moment, there are two ways to find out whether you own the identity yet or not:

1. Try and have someone else use your nomicle in some way (e.g. sending you a message via xTalk and seeing if you successfully receive it)
2. [Run the Block Explorer](explorer.md), which displays whether or not you are the owner amongst the output it prints out

### Running on Mac Startup

Nomicle requires elevated privileges to run on macOS because it writes to system directories (inside `/usr/local/`). A feature of macOS called System Integrity Protection won't allow Nomicle to write to files at that location otherwise.

When you restart your Mac, the easiest thing to do would be to run `$ sudo ./start.sh` yourself using Terminal. If you're feeling adventurous, tutorials exist online to show you how to run the script with elevated privileges. However, this guide is written with the goal of simplicity in mind, so such an exercise is left to the discretion of the reader.

## Linux

1. Download and install [Python 3](https://www.python.org/download/releases/3.0/) if you don't already have it installed. To find out:
   - Launch the terminal
   - Inside the terminal, type "python3". If you get an error, that means Python is probably not installed. Use your favourite web search engine to find out how to install Python 3 on your Linux distro

2. Assuming Python 3 is now running in your terminal window:
   - Make sure the displayed Python version number is of the form 3.x or 3.x.x (where "x" can be any number)
   - Install the [cryptography](https://cryptography.io/en/latest/) Python package by following the instructions on the project's website
   - You may then quit Python by typing "quit()" and pressing the Return key

3. [Download the Nomicle Complete Bundle for macOS/Linux](download.md#complete-bundles) and extract it into a directory called `Nomicle`. The final folder structure should look something like this:

   ```
   Nomicle/
   ├── PyNomicle/
   │   └── nomicle.py
   ├── fort.py
   ├── LICENSE
   ├── seed.py
   ├── start.sh
   └── stop.sh
   ```

4. You are now ready to run Nomicle on your computer:
   - In the terminal window, navigate to the Nomicle directory you extracted
   - An easy way to do this is to type "cd " (there's a space after the "cd") and then drag the directory from your shell window and drop it over the cursor inside the terminal
   - The terminal should insert the path to the directory at the cursor (it's also possible your terminal app doesn't support this, in which case you need to either paste or type the path)
   - Press the Return key

5. Type the following (pressing the Return key after you enter each line; do not include the "$" character in what you type):

   ```bash
   sudo chmod u+x start.sh
   sudo chmod u+x stop.sh
   sudo chmod u+x fort.sh
   sudo chmod u+x seed.sh
   sudo ./start.sh
   ```

   - You will be prompted to enter the password you use to log into your computer after you enter the first line because "sudo" is a command that uses administrator privileges
   - *If you get a firewall alert, make sure to allow it through otherwise you won't be able to connect to the Nomicle network. **Nomicle uses port 1992 by default so make sure to allow UDP traffic over that port number.***
   - The next step is to set your Nomicle identifier

6. Set your Nomicle identifier:
   - Your Nomicle identifier can be any text that you think can be unique enough for others to find you (e.g. your favourite username or your email address)
   - The more unique your identifier, the more likely it is you will always own it and can start using it right away
   - Inside the terminal, type (and press Return at the end):

     ```bash
     nano /usr/local/share/ncle/id
     ```

   - This will open the file in the nano text editor (feel free to use whichever text editor you otherwise prefer)
   - Type in your chosen identifier, then save and quit nano
   - You can change this identifier to something else whenever you want later on

7. That's it! You're now all set to run Nomicle-powered programs:
   - To get a feel for it, [download and run xTalk](https://github.com/alimahouk/xtalk), a Nomicle-powered messaging system
   - Nomicle runs in the background on your computer, and it is recommended that you leave it that way so long as your computer is running to allow the Fortifier to fortify your identity and help you maintain its ownership
   - To stop the Nomicle programs at any time, run the `stop.sh` script
   - Note that this will only work if you had started the programs using `start.sh`, otherwise you need to kill the Fortifier and Seeder processes yourself

*Note: depending on whether someone else already owns a stronger version of your chosen identifier, you may not necessarily own the identity anytime soon after you start your own fortification of it. It may take a while depending on how much processing power the current owner has already invested in it as well as how long you leave the Fortifier running on your own computer.*

At the moment, there are two ways to find out whether you own the identity yet or not:

1. Try and have someone else use your nomicle in some way (e.g. sending you a message via xTalk and seeing if you successfully receive it)
2. [Run the Block Explorer](explorer.md), which displays whether or not you are the owner amongst the output it prints out

### Running on Computer Startup

Follow the steps mentioned in [this Ask Ubuntu post](https://askubuntu.com/a/956539). The contents of your `rc.local` file should look something like:

```bash
#!/bin/sh -e
./replace/this/with/the/actual/path/to/start.sh
exit 0
```

You can check if this method works by running the following command in the terminal when you restart your computer:

```bash
ps aux | grep python
```

You should see the Fortifier and Seeder running as two Python processes.
