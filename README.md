# Network Security Log Analyser
___

## Description
This is a PySimpleGUI-based Python software tool for processing and visualising selected Windows Event Security.evtx log files that meet a conditions in Event ID 4688.
>>>>>>1) The end-user sets up their username and password to create an account for security puposes.
>>>>>>2) The username and password must match to progress to being able to process the Windows Event Security.evtx log files if certain conditions are met.
>>>>>>3) The end-user then is prompted to browse, select and import a Security.evtx log file to be processed.
>>>>>>4) To parse and analyse the EVTX log file it must conditions set for Event ID 4688 that is then returned to a dictionary.
>>>>>>5) The last step is to visualise the analysed data which will be illustrated as a histogram.  
___

## Author
Emanuel Martin Mathurine (w1229113), 6ELEN016W, © University of Westminster 2022/2023
* [LinkedIn/MartinMathurine](https://www.linkedin.com/in/martinmathurine)
* [GitHub/MartinMathurine](https://github.com/Martin199X)
___

## Required Files
>>>>>To use your own Security.evtx log file you can export it from Windows Event Viewer and save the file to a trusted location.
* Network Security Log Analyser.py
* Security.evtx (contains Event ID 4688 that meets the conditions set in the script)
* Securityv2.evtx (does not contain any Event ID 4688 events that meet conditions set in the script, therefore, the app will have an alternative outcome -- for testing purposes)
___

## Installation
>>>>>>Use the package manager to run [pip](https://pip.pypa.io/en/stable/) install evtx, matplotlib, PySimpleGUI and lxml packages in a command-line interface. Depending on the operating system, use Terminal on a Mac and Command Prompt on Windows.
```cmd / terminal
pip install evtx
pip install matplotlib
pip install PySimpleGUI
pip install lxml
```
___

## Usage
```python3
import datetime  # working with dates and times
import re  # working with regex
import sys # terminating the interpreter in python

import matplotlib.pyplot as plt  # creating various types of graphs and plots
import PySimpleGUI as sg  # creating a gui for the app for increased usability
from evtx import PyEvtxParser  # parsing and analysing evtx log files
from lxml import etree  # parsing data in events generated from xml content
```
___

## System Requirements
This utility works on all Windows, macOS and Linux operating systems compatible with Python 3.7 onwards. Both 32-bit and 64-bit platforms are supported as well as macOS arm64 (m1).
___

## Version History
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
* Suspected issue with imported evtx parser. Will try others through trial and error to find one that works.
* The app does not run.
___

### v2.1
* Issue with getting data from dictionary to plot a histogram. Visualising the analysed data failed.
* Multiple Python3 syntax errors and debugging problems found -- needs fixing.
* Suspected issue with imported evtx parser. Will try others through trial and error to find one that works.
* Removed os import as it is not used anymore.
* Edited the PySimpleGUI code block to better reflect how I want the software tool to be used.
* The app still does not run.
___

### v2.2
* Used evtx parser again from revision 2.0 -- no success running the app. Possibly a configuration issue?
* Issue with getting data from dictionary to plot a histogram. Visualising the analysed data failed.
* Multiple Python3 syntax errors and debugging problems found -- needs fixing.
* Suspected issue with imported evtx parser. Will try others through trial and error to find one that works.
* Edited the PySimpleGUI code block to better reflect how I want the software tool to be used.
* The app still does not run.
___

### v2.3
* Used an amended iteration of the evtx parser importing a specific module for parsing log file -- SUCCESS!!
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
* With larger log files such as the Securityv2.evtx log file that I supplied it takes longer to process,but , this is expected.
* No end-user authentication implemented to provide a layer of security.
* The software tool does indeed notify the end-user, however, it would be a nice quality-of-life firmware update if they were emailed or messaged the outcome which may be useful in an enterprise when log files are much larger and could take a considerable amount of time to process.
___

### v3.0 (First Release)
* End-user authentication implemented in the form of a username and password. Useful for a security analyst.
* Some non app breaking text typos are corrected and verbiage edited for clarity.
* The PySimpleGUI generated windows are edited to have the same aesthetic brand identity.
* Create a user account upon authentication condition of password.
* Limitation from revision v2.4 corrected in line 89 and 125-126 to terminate script if the GUI is closed.
* Imported the sys module so that I can terminate the Python interpreter from running for security circumvention purposes.
* Bug found by manually and meticulously going through script to discover that choosing to analyse data in lines 210-211. This was solved with a simple if-not statement improving usablity. 
* Packaged this python script as an executable standalone .exe file so that the script isn't visible for security circumvention purposes. Useful for entering private information such as username and password credentials.

#### Limitations:
* Testing With larger log files such as the Securityv2.evtx log file that I supplied it takes longer to process, but, this is expected.
* The software tool does indeed notify the end-user, however, it would be a nice quality-of-life firmware update if they were emailed or messaged the outcome which may be useful in an enterprise when log files are much larger and could take a considerable amount of time to process.
* Created user accounts' username and password are not saved. Could be saved to a file to match credentials from a dictionary so user does not need to create a new login account everytime they use the tool.
* Executable version of the software tool is not password protected to prevent unauthorised access from potential unauthorised third parties. 
___

## References: 
* [01] Log File Analysis with Python. [Pluralsight](https://www.pluralsight.com/courses/python-log-file-analysis). Accessed 01 Apr. 2023.
* [02] PySimpleGUI Tutorial. [TutorialsPoint](https://www.tutorialspoint.com/pysimplegui/index.htm). Accessed 19 Apr. 2023.
* [03] Ben-Amram [omerbenamram@gmail.com](mailto:omerbenamram@gmail.com), Omer. Evtx: Python Bindings for [Github](Https://Github.Com/Omerbenamram/Evtx). MacOS :: MacOS X, POSIX.
* [04] Grav - Markdown Syntax. [TutorialsPoint](https://www.tutorialspoint.com/grav/grav_markdown_syntax.htm). Accessed 19 Apr. 2023.
* [05] ‘Datetime — Basic Date and Time Types’. Python Documentation, [Python](https://docs.python.org/3/library/datetime.html). Accessed 19 Apr. 2023.
* [06] vinaypamnani-msft. 4688(S) A New Process Has Been Created. (Windows 10). 16 Dec. 2022, [Microsoft](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4688).
* [07] ‘Re — Regular Expression Operations’. Python Documentation, [Python](https://docs.python.org/3/library/re.html). Accessed 19 Apr. 2023.
* [08] Windows Security Log Event ID 4688 - A New Process Has Been Created. [UltimateWindowsSecurity](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4688). Accessed 19 Apr. 2023.
* [09] W. Ballenthin, “python-evtx,” GitHub, Apr. 17, 2023. [GitHub](https://github.com/williballenthin/python-evtx). Accessed 19 Apr. 2023.
* [10] Desai, Bhargav. ‘Login Authenticator'. Stack Overflow, 19 Oct. 2020, [StackOverflow](https://stackoverflow.com/a/64426586). Accessed 19 Apr. 2023.
* [11] ‘Make a README’. Make a README, [MakeAREADME](https://www.makeareadme.com. Accessed 19 Apr. 2023.
* [12] PySimpleGUI - Password Protect Your Program, [YouTube: The CS Classroom](https://www.youtube.com/watch?v=Nya7yHlv-Ng). Accessed 19 Apr. 2023.
* [13] Chaturvedi, Anubhav. ‘Building a Login GUI App in Python with Encrypted Credentials Saving Functionality’. Medium, 20 Dec. 2021, [Medium](https://consultanubhav-1596.medium.com/building-a-login-gui-app-in-python-with-encrypted-credentials-saving-functionality-dfefec18cbb1). Accessed 19 Apr. 2023.
___

### Declaration
I hereby declare that unless otherwise indicated, all work included in this individual project was of the author. All sources, references and literature used will be properly cited and referenced completely due to the source. Emanuel. M. Mathurine. © University of Westminster 2022/2023
