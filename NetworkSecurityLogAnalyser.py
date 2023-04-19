# README
# Filename: NetworkSecurityLogAnalyser.py
# Arbitrary Version: v3.0 (First Release)
# Author: Emanuel Martin Mathurine (w1229113), 6ELEN016W, © University of Westminster, 2022/2023
# LinkedIn: https://www.linkedin.com/in/martinmathurine
# Github: https://github.com/Martin199X
# Description: This is a PySimpleGUI-based Python software tool for processing and visualising selected Windows Event
#              Security.evtx log files.
# Updates: * v3.0 (First Release).
#          * End-user authentication implemented in the form of a username and password. Useful for a security analyst.
#          * Some non app breaking text typos are corrected and verbiage edited for clarity.
#          * The PySimpleGUI generated windows are edited to have the same aesthetic brand identity.
#          * Create a user account upon authentication condition of password.
#          * Limitation from revision v2.4 corrected in line 89 and 125-126 to terminate script if the GUI is closed.
#          * Imported the sys module so that I can terminate the Python interpreter from running for security
#          circumvention purposes.
#          * Bug found by manually and meticulously going through script to discover that choosing to analyse data in.
#          lines 210-211. This was solved with a simple if-not statement improving usablity.
#          * Packaged this python script as an executable standalone .exe file so that the script isn't visible for
#          security circumvention purposes.
# Limitations:
#              * Testing With larger log files such as the Securityv2.evtx log file that I supplied it takes longer
#              to process, but, this is expected.
#              * The software tool does indeed notify the end-user, however, it would be a nice quality-of-life
#              firmware update if they were emailed or messaged the outcome which may be useful in an enterprise
#              when log files are much larger and could take a considerable amount of time to process.
#              * Created user accounts' username and password are not saved. Could be saved to a file to match
#              credentials from a dictionary so user does not need to create a new login account everytime they use
#              the tool.
# Installation: Use the package manager [pip](https://pip.pypa.io/en/stable/) to install evtx, matplotlib, PySimpleGUI
#               and lxml packages in a command-line interface. Depending on the operating system, use Terminal on a Mac
#               and Command Prompt (CMD) on Windows.
#               *pip install evtx
#               *pip install matplotlib
#               *pip install PySimpleGUI
#               *pip install lxml

# Import Modules---------------------------
from datetime import datetime as dt  # Working with dates and times. Refactored for more concise code
import re  # Working with regex
import sys  # Terminating the interpreter in python

import matplotlib.pyplot as plt  # Creating various types of graphs and plots
import PySimpleGUI as sg  # Creating a gui for the app for increased usability
from evtx import PyEvtxParser  # Parsing and analysing evtx log files
from lxml import etree  # Parsing data in events generated from xml content

# Main Body-------------------------------------------------
# PyInstaller Command = pyinstaller NetworkSecurityLogAnalyser.py -n Main --windowed --noconfirm --clean
# Command to package this python script as an executable standalone .exe file
username = ''  # Empty variable for username input field
password = ''  # Empty variable for password input field


def progress_bar():  # Progress bar function
    sg.theme('DarkTeal2')  # Window theme
    layout = [[sg.Text('Account Created!', font=("Arial", 12, "bold"))],  # Successful account creation window
              [sg.ProgressBar(1000, orientation='h', size=(20, 20), key='progbar')],
              # Creates horizontal progress bar widget with
              [sg.Cancel(font=("Arial", 12, "bold"))]]
    # Creates a window for my app with a title name
    window = sg.Window('Loading...', layout)  # Loading screen / progress bar for account creation
    for i in range(1000):  # For loop in a range of 1000. It will take the place of the next 999 integer values
        event, values = window.read(timeout=1)  # Time to wait for event
        if event == sg.WIN_CLOSED or event == 'Cancel':  # For loop condition
            break  # Break loop
        window['progbar'].update_bar(i + 1)  # Incremental update of the progress bar in the for loop
    window.close()


def create_account():
    global username, password
    sg.theme('DarkTeal2')
    layout = [[sg.Text("Account Sign Up", size=(15, 1), font=("Arial", 16, "bold"))],
              # Account creation sign up window
              [sg.Text("Create Username", tooltip='Type Username', size=(15, 1), font=("Arial", 12)),
               sg.InputText(key='-username-', font=("Arial", 12))],
              [sg.Text("Create Password", tooltip='Type Password', size=(15, 1), font=("Arial", 12)),
               sg.InputText(key='-password-', font=("Arial", 12), password_char='*')],
              [sg.Text("Re-enter Password", tooltip='Retype Password', size=(15, 1), font=("Arial", 12)),
               sg.InputText(key='-repassword-', font=("Arial", 12), password_char='*')],
              [sg.Button("Submit", expand_x=True, tooltip='Create Account', font=("Arial", 12, "bold")),
               sg.Button("Cancel", expand_x=True, tooltip='Cancel Account Creation', font=("Arial", 12, "bold"))]]
    # Creates a window for my app with a title name
    window = sg.Window("Network Security Log Analyser v3.0", layout)

    while True:
        event, values = window.read()
        if event == sg.WIN_CLOSED or event == 'Cancel':
            sys.exit()  # If user closes the window the app terminates and does not allow user to process log files
        else:
            if event == "Submit":
                password = values['-password-']  # Password needs to match
                username = values['-username-']  # Username needs to match
                if values['-password-'] != values['-repassword-']:  # No progress if password condition not met
                    sg.popup_error("Account Password Incorrect, Try Again!", font=("Arial", 12, "bold"))
                    # Password incorrect prompt
                    continue
                elif values['-password-'] == values['-repassword-']:  # Condition for password to match for progress
                    progress_bar()  # Produces a progress bar to prompt user for next step
                    break
    window.close()


create_account()  # Creates the user account upon authentication


def login():  # Function for created accounts to authenticate their credentials
    global username, password  # Global variables in authorisation username and password
    sg.theme("DarkTeal2")
    layout = [[sg.Text("Account Log In", size=(15, 1), font=("Arial", 16, "bold"))],  # Window title
              [sg.Text("Username", tooltip='Enter Username', size=(15, 1), font=("Arial", 12)),
              sg.InputText(key='-usrnm-', font=16)],  # Input username field
              [sg.Text("Password", tooltip='Enter Password', size=(15, 1), font=("Arial", 12)),
              sg.InputText(key='-pwd-', password_char='*', font=16)],  # Input password field
              [sg.Button('Confirm', expand_x=True, tooltip='Confirm Login ID', font=("Arial", 12, "bold")),
              sg.Button('Cancel', expand_x=True, font=("Arial", 12, "bold"))]]  # Confirm or cancel login credentials
    # Creates a window for my app with a title name
    window = sg.Window("Network Security Log Analyser v3.0", layout)
    # For future application revision update: store login info in a locally stored external file so that a dictionary
    # Can be searched for past account holders the variable can be called from a spreadsheet or csv file locally

    while True:
        event, values = window.read()  # Read events and values in this PySimpleGui window
        if event == "Cancel" or event == sg.WIN_CLOSED:
            # Condition if cancel selected or window closed the application will terminate
            sys.exit()  # If user closes the window the app terminates and does not allow user to process log files
        else:
            if event == "Confirm":  # Determine if confirm is selected
                if values['-usrnm-'] == username and values['-pwd-'] == password:  # Condition for matching credentials
                    sg.popup("Access Granted!", font=("Arial", 12, "bold"))  # Access granted popup if credentials match
                    break  # breaks the loop
                elif values['-usrnm-'] != username or values['-pwd-'] != password:  # Does username and password match?
                    sg.popup("Incorrect Login, Try Again!", font=("Arial", 12, "bold"))  # Prompt for another attempt
    return True  # Return a true statement if the account login is successful


login()


sg.theme("DarkTeal2")  # PySimpleGui aesthetic theme
# PySimpleGui gui window. includes button to browse for an input.evtx log file and another button to visualise the log
layout = [[sg.Text("Network Security Log Analyser", size=(30, 1), font=("Arial", 16, "bold"))],
          [sg.FileBrowse('Input EVTX', key="-evtxlogfile-", tooltip='Find Security.evtx', font=("Arial", 12, "bold")),
           # Input for log file to be parsed, analysed and cleaned
           sg.Button('Analyse Data', expand_x=True, tooltip='Plot Histogram', font=("Arial", 12, "bold")),
           # The analysed security evtx log file that met conditions for event id 4688 will be plotted on a histogram
           sg.Button('Cancel', expand_x=True, tooltip='Exit Application', font=("Arial", 12, "bold"))],
          # Option to exit the application after processing log files
          [sg.Text("Author: Emanuel Martin Mathurine (w1229113)", font=("Arial", 10, "bold"))],
          # Script author: emanuel martin mathurine (w1229113)
          [sg.Text("Institution: © University of Westminster, 2022/2023", font=("Arial", 10, "bold"))],
          # University institution
          [sg.Text("Module Code: 6ELEN016W", font=("Arial", 10, "bold"))]]  # module code for academic year 2022/2023
# Creates a window for my app with a title name
window = sg.Window('Network Security Log Analyser', layout, size=(600, 200))


# parseEvtx is defined to extrapolate information from a parsed log file and store it to a dictionary.
# The parsed data is extrapolated from the System's EventID and TimeCreated tags in addition to the EventData tags.
def parseEvtx(event):
    sys_tag = event.find("System", event.nsmap)  # Extract system tag of the windows event schema using find function
    event_id = sys_tag.find("EventID", event.nsmap)  # Run find function again on the eventid value
    event_ts = sys_tag.find("TimeCreated", event.nsmap)  # run find function again on the timecreated value
    event_data = event.find("EventData", event.nsmap)  # run find function again on the eventdata value
    r = {}  # empty dictionary for stored values
    r["ts"] = event_ts.values()[0]  # assign ts to the dictionary for the timecreated tag's timestamp value
    r["eid"] = event_id.text  # assign eid to the dictionary for the text value of the eventid tag
    for data in event_data.getchildren():  # iterate through for loop event_data tag containing an array of nested-
        # tag objects extracted by getchildren function
        r[data.attrib["Name"]] = data.text  # the key in the dictionary with an attribute appended to it
    return r  # returns to dictionary containing the parsed data from Windows Event log files


# the openEvtxFile function uses the log_folder parameter to open the log file and makes log entries for the parsed log
# using the yield statement.
def openEvtxFile(logs_folder):  # function can open and parse evtx log files and will yeild an xml object to be parsed
    parser = PyEvtxParser(logs_folder)  # added an evtx parser for logs_folder evtx file
    for record in parser.records():  # for loop that loops through parsed records from the log file
        yield etree.fromstring(bytes(record['data'], encoding='utf8'))
        # parses specifically the data field of an event in xml and returns it to the dictionary encoded in utf-8.


def detectRundll32(logs_folder):  # Function to detect rundll32 processes from parsed evtx log file
    log_file = openEvtxFile(logs_folder)  # The log file inputted by the user is opened and assigned a value
    rundll32_logs = []  # Empty array
    for log_entry in log_file:  # For loop to loop through the EVTX log file for parsing
        try:
            log_data = parseEvtx(log_entry)  # Parse the log entry
            if log_data["eid"] == "4688" and log_data["CommandLine"]:
                # Look for log entries that are event id 4688 and has a commandline field present -- not none
                if "rundll32" in log_data["NewProcessName"] and re.search("powershell|cmd", log_data["ParentProcessName"]):
                    # The detectRundll32 function checks for new process names in Event ID 4688 and parent process name
                    # of powershell or cmd storing matching data in a list. also uses regex search function to
                    # find the parameters for the log_data variable.
                    rundll32_logs.append(log_data)  # Appends the matching parsed log data into the array.
        except:  # Catch exceptions and continue without stopping parsing and analysing the log data regardless
            pass

    return rundll32_logs  # Returns array of logs that met condition to dictionary


# Event loop to process events and get the values of the input then visualises the parsed, analysed and cleaned data
# into a histogram.
while True:  # Display and interact with the created window using an event loop
    event, values = window.read()
    # Event name fixed 'Cancel' instead 'Cancel'
    if event == sg.WIN_CLOSED or event == 'Cancel':  # If window was closed or uses selects cancel the utility closes
        break

    # If the user chooses to visualise the analysed log data then its values = evtxlogfile to parse/analyse log file
    if event == 'Analyse Data':  # If statement to check if analyse data is selected or not
        logs_folder = values["-evtxlogfile-"]  # The inputted evtx log file
        if not logs_folder:  # Ensure input file has been selected otherwise the app throws an error terminating itself
            continue  # Continue if condition is met
        rundll32_logs = detectRundll32(logs_folder)  # detectRundll32 function parses through log file that match
        # Condition set in previous function's for loop -- line 168
        if rundll32_logs:  # If statement for logs tha meet previous function's condition
            # Timestamps convert to datetime objects from the rundll32_logs
            timestamps = [dt.strptime(log["ts"], "%Y-%m-%dT%H:%M:%S.%fZ") for log in rundll32_logs]
            # Fixed datetime format and also refactored datetime module
            fig = plt.figure(figsize=(8, 8))  # Change size of matplotlib window that draws histogram
            plt.hist(timestamps, bins='auto', color='#5FD85F', rwidth=0.85)  # Creates histogram with clearer spacing
            plt.xlabel("Timestamp")  # X-axis label for histogram plot
            plt.ylabel("Frequency")  # Y-axis label for histogram plot
            plt.title(f"Rundll32 Process Executed with CLI (Event Count={len(timestamps)})")  # Histogram plot title
            # adds total occurances of events that meet condition
            plt.xticks(rotation=20)  # Timestamps on the x-axis visually clearer to read. rotated at 20-degree angle
            plt.show()  # Creates matplotlib window to plot histogram

        else:  # Else statement to produce a popup window prompt if no conditions are met
            sg.Popup("No Rundll32 Processes Executed by CLI Found", font=("Arial", 12, "bold"))  # cli=powershell or cmd

# The end------------------------------------------------
window.close()
