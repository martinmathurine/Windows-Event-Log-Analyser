# Windows Event Log Analyser (Network Security EVTX Log Analyser)
___
## Author
Martin Mathurine (w1229113), 6ELEN016W, © University of Westminster 2022/2023
* [LinkedIn/MartinMathurine](https://www.linkedin.com/in/martinmathurine)
* [GitHub/MartinMathurine](https://github.com/Martin199X/Windows-Event-Log-Analyser)
___
## Description
This is a PySimpleGUI-based Python software tool for processing and visualising selected Windows Event Security.EVTX log files that meet a conditions in Event ID 4688.
>>>>>>01) The end-user sets up their username and password to create an account for security purposes.
>>>>>>02) The username and password must match to progress to being able to process the Windows Event Security.EVTX log files if certain conditions are met.
>>>>>>03) The end-user then is prompted to browse, select and import a Security.EVTX log file to be processed.
>>>>>>04) To parse and analyse the EVTX log file it must conditions set for Event ID 4688 that is then returned to a dictionary.
>>>>>>05) The last step is to visualise the analysed data which will be illustrated as a histogram.  
>>>>>>06) Supports 32-bit and 64-bit systems.
>>>>>>07) Reliable and supports EVTX log files up to the recommended 4 GB file size.
>>>>>>08) Windows Event Sources (Security).
>>>>>>09) Filtering with regex.
>>>>>>10) Data visualisation as histogram.
___
## User Guide

Account Sign Up - The user inputs their username and password.

<img src="https://i.imgur.com/EXe95nD.png" width="500">

Log In - Upon successful log in, the user confirms stored secret account credentials to gain access to application.

<img src="https://i.imgur.com/Qrl7oTe.png" width="500">

Analyse EVTX Log File Data - The user is prompted to input an EVTX security log file for in preparation for log file analysis.

<img src="https://i.imgur.com/JOQO4fe.png" width="500">

Visualise Analysed EVTX Log File Data - The user is prompted to output analysed results for data visualisation as a plotted histogram.

<img src="https://i.imgur.com/YK64t4C.png" width="500">

Visualised Results - Matplotlib plots a histogram of the analysed log data with intelligibly visualised information

<img src="https://i.imgur.com/ctyQLO0.png" width="500">

___
## Required Files
>>>>>To use your own Security.EVTX log file you can export it from Windows Event Viewer and save the file to a trusted location.
* Network Security Log Analyser.py
* Security.EVTX (contains Event ID 4688 that meets the conditions set in the script)
* Securityv2.EVTX (does not contain any Event ID 4688 events that meet conditions set in the script, therefore, the app will have an alternative outcome -- for testing purposes)
___

## Installation
>>>>>>Use the package manager to run [pip](https://pip.pypa.io/en/stable/) install evtx, matplotlib, PySimpleGUI and lxml packages in a command-line interface. Depending on the operating system, use Terminal on a Mac and Command Prompt on Windows.
```cmd / terminal
pip install evtx
pip install matplotlib
pip install PySimpleGUI
pip install lxml
pip install PyInstaller
```
___

## Usage
```python3
import datetime  # working with dates and times
import re  # working with regex
import sys # terminating the interpreter in python

import matplotlib.pyplot as plt  # creating various types of graphs and plots
import PySimpleGUI as sg  # creating a gui for the app for increased usability
from evtx import PyEvtxParser  # parsing and analysing EVTX log files
from lxml import etree  # parsing data in events generated from xml content
```
___

## System Requirements
This utility works on modern Windows, macOS and Linux operating systems compatible with Python 3.7 onwards. Both 32-bit and 64-bit platforms are supported as well as macOS arm64 (m1). EVTX log files can be sourced from your local machine, remote computers, and external .EVTX log files. Recommended 8 GB RAM or more. Minimum at least 4 GB RAM.

___

## Pseudocode
```Pseudocode
# Account creation
Display "Sign Up" window
User inputs username and password
If password or username is empty
    It is not valid
Elif password does not match
    It is not valid
Elif password match
    It is valid
Usernames and passwords are stored in a dictionary

# Progress bar
Display "Progress Bar" window
Horizontal display showing incremental progress until 100% is reached to signify account creation
Display "Account Created" window

# Log in
Display "Log In" window
User confirms secret username and password
If account password is valid:
    Continue to next window to perform log file analysis and data visualisation
    Display a progress bar
Else:
    Display error message and prompt user to try again if log in credentials are wrong
    If "Cancel" button is selected exit software tool
Display "Access Granted" window

# EVTX log file analysis and data visualisation
Display "Network Security Log Analyser" window
User inputs EVTX security log files sourced from Windows Event Viewer
User selects to analyse and visualise EVTX security log file for Event ID 4688 events that meet conditions set in function
If events that conditionally are met:
    Plot histogram
    Display plotted histogram in window
Else:
    Display "No Rundll32 Processes Executed by CLI Found" message

# Function to parse EVTX security log files for Event ID 4688
def parseevtx(event):
    Parse Event ID 4688 events
    If conditional matches are found:
        Store in a dictionary

# Function to encode the EVTX log file data and encode it in utf-8 to process Event ID 4688 events
def openevtxfile(logs_folder):
    Parse the data field of an event in XML and returns events to the dictionary encoded in utf-8

# Function to find matches for condition from parsed log file to analyse it for events to be stored in a list
def detectrundll32(logs_folder):
    Use regex to find Rundll32 processes in the events and store the matching data in a list
    Return the list of logs that met condition to dictionary

# A while loop to perform matplotlib's functionality to plot a histogram for the end-user
While loop to plot histogram with matplotlib module
    Matplotlib uses the inputted EVTX security log file to visualise the analyed data
Display plotted histogram window
```
___

## Release Notes
### v1.0
* Able to parse and analyse log data successfully.
* Issue with getting data from dictionary to plotted bar chart. Visualising the analysed log data failed.
* Multiple Python3 syntax errors and debugging problems found -- needs fixing in next revision.
* The app does not run.
___

### v2.0
* Replaced the broken bar chart function from revision 1.0 now with a while loop to instead draw a histogram.
* Issue with getting data from dictionary to plot a histogram. Visualising the analysed data failed.
* Multiple Python3 syntax errors and debugging problems found -- needs fixing.
* Suspected issue with imported EVTX parser. Will try others through trial and error to find one that works.
* The app does not run.
___

### v2.1
* Issue with getting data from dictionary to plot a histogram. Visualising the analysed data failed.
* Multiple Python3 syntax errors and debugging problems found -- needs fixing.
* Suspected issue with imported EVTX parser. Will try others through trial and error to find one that works.
* Removed os import as it is not used anymore.
* Edited the PySimpleGUI code block to better reflect how I want the software tool to be used.
* The app still does not run.
___

### v2.2
* Used EVTX parser again from revision 2.0 -- no success running the app. Possibly a configuration issue?
* Issue with getting data from dictionary to plot a histogram. Visualising the analysed data failed.
* Multiple Python3 syntax errors and debugging problems found -- needs fixing.
* Suspected issue with imported EVTX parser. Will try others through trial and error to find one that works.
* Edited the PySimpleGUI code block to better reflect how I want the software tool to be used.
* The app still does not run.
___

### v2.3
* Used an amended iteration of the EVTX parser importing a specific module for parsing log file -- SUCCESS!!
* Visualising analysed data from returned dictionary to plot a histogram has been solved -- SUCCESS!!
* Meticulously solved and fixed syntax errors and debugging problems -- SUCCESS!!
* Forgot to pip install lxml package needed for parsing the xml content from the event's data field in line 65
* The app now successfully runs but is not visually clear and has some usability issues.
* Imports are sorted for readability and user maintenance purposes.
* Fixed datetime format.
* Produced histogram on x-axis (timestamps) are visually cluttered together -- it is not clear to read.
* The app runs successfully!!
___

### v2.4
* Added total number of events that meet condition in histogram to be shown in title.
* Added more spacing between the histogram's bars if more occurrences are found.
* Some non app breaking text typos are corrected and verbiage edited for clarity.
* Timestamp labels on the x-axis are visually clearer to read now since I have repositioned the ticks.
* The histogram colour was changed to green to match the colour scheme of the software tool aesthetically.
* The histogram window created by matplotlib is now larger for visually clarity and readability.
* The PySimpleGUI window is now larger to accommodate for visual clarity and aesthetics.
* Confirmed to be compatible with older Python3 interpreters [my script is written in Python3].
#### Limitations:
* With larger log files such as the Securityv2.EVTX log file that I supplied it takes longer to process, but, this is expected due to 32-bit and 64-bit operating systems.
* No end-user authentication implemented to provide a layer of security.
* The software tool does indeed notify the end-user, however, it would be a nice quality-of-life firmware update if they were emailed or messaged the outcome which may be useful in an enterprise when log files are much larger and could take a considerable amount of time to process.
___

### v3.0 (First Release)
* End-user authentication implemented in the form of a username and password. Useful for a security analyst.
* Some non app breaking text typos are corrected and verbiage edited for clarity.
* The PySimpleGUI generated windows are edited to have the same aesthetic brand identity.
* Create a user account upon authentication condition of password.
* Limitation from revision v2.4 corrected in line 90 and 126-127 to terminate script if the GUI is closed.
* Imported the sys module so that I can terminate the Python interpreter from running for security circumvention purposes.
* Performed ad-hoc testing which allowed me to find a bug by manually and meticulously going through script to discover that choosing to analyse data in lines 214-215. This was solved with a simple if-not statement improving usability. 
* Packaged this python script as an executable standalone .exe file so that the script isn't visible for security circumvention purposes. Useful for entering private information such as username and password credentials.

#### Limitations:
* Testing With larger log files such as the Securityv2.EVTX log file that I supplied it takes longer to process, but, this is expected not so much a limitation but a side effect of processing large files.
* The software tool does indeed notify the end-user, however, it would be a nice quality-of-life firmware update if they were emailed or messaged the outcome which may be useful in an enterprise when log files are much larger and could take a considerable amount of time to process.
* Created user accounts' username and password are not saved. Could be saved to a file to match credentials from a dictionary so user does not need to create a new login account every time they use the tool.
* Executable version of the software tool is not password protected to prevent unauthorised access from potential unauthorised third parties. 
___

## References: 
* [01] Log File Analysis with Python. [Pluralsight](https://www.pluralsight.com/courses/python-log-file-analysis). Accessed 01 Apr. 2023.
* [02] PySimpleGUI Tutorial. [TutorialsPoint](https://www.tutorialspoint.com/pysimplegui/index.htm). Accessed 01 Apr. 2023.
* [03] Ben-Amram [omerbenamram@gmail.com](mailto:omerbenamram@gmail.com), Omer. Evtx: Python Bindings for [Github](Https://Github.Com/Omerbenamram/Evtx). MacOS :: MacOS X, POSIX. Accessed 01 Apr. 2023.
* [04] Grav - Markdown Syntax. [TutorialsPoint](https://www.tutorialspoint.com/grav/grav_markdown_syntax.htm). Accessed 01 Apr. 2023.
* [05] ‘Datetime — Basic Date and Time Types’. Python Documentation, [Python](https://docs.python.org/3/library/datetime.html). Accessed 19 Apr. 2023.
* [06] vinaypamnani-msft. 4688(S) A New Process Has Been Created. (Windows 10). 16 Dec. 2022, [Microsoft](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4688). Accessed 01 Apr. 2023.
* [07] ‘Re — Regular Expression Operations’. Python Documentation, [Python](https://docs.python.org/3/library/re.html). Accessed 01 Apr. 2023.
* [08] Windows Security Log Event ID 4688 - A New Process Has Been Created. [UltimateWindowsSecurity](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4688). Accessed 01 Apr. 2023.
* [09] W. Ballenthin, “python-evtx,” GitHub, Apr. 17, 2023. [GitHub](https://github.com/williballenthin/python-evtx). Accessed 01 Apr. 2023.
* [10] Desai, Bhargav. 'Login Authenticator'. Stack Overflow, 19 Oct. 2020, [StackOverflow](https://stackoverflow.com/a/64426586). Accessed 01 Apr. 2023.
* [11] ‘Make a README’. Make a README, [MakeAREADME](https://www.makeareadme.com. Accessed 01 Apr. 2023.
* [12] PySimpleGUI - Password Protect Your Program, [YouTube: The CS Classroom](https://www.youtube.com/watch?v=Nya7yHlv-Ng). Accessed 01 Apr. 2023.
* [13] Chaturvedi, Anubhav. ‘Building a Login GUI App in Python...’. Medium, 20 Dec. 2021, [Medium](https://consultanubhav-1596.medium.com/building-a-login-gui-app-in-python-with-encrypted-credentials-saving-functionality-dfefec18cbb1). Accessed 01 Apr. 2023.
* [14] Python, Real. Getting Started With Testing in Python. [Real Python](https://realpython.com/python-testing/). Accessed 01 Apr. 2023.
___

### Declaration
I hereby declare that unless otherwise indicated, all work included in this individual project was of the author. All sources, references and literature used will be properly cited and referenced completely due to the source. M. Mathurine. © University of Westminster 2022/2023
