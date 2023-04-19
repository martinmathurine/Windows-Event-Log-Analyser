# README
# Filename: app v2.3.py
# Arbitrary Version: v2.3
# Author: Emanuel Martin Mathurine (w1229113), 6ELEN016W, © University of Westminster, 2022/2023
# LinkedIn: https://www.linkedin.com/in/martinmathurine
# Github: https://github.com/Martin199X
# Description: This is a PySimpleGUI-based Python software tool for processing and visualising selected Windows Event
#              Security.evtx log files.
# Updates: * Revision v2.3.
#          * Used an amended iteration of the evtx parser importing a specific module for parsing log file -- SUCCESS!!
#          * Visualising analysed data from returned dictionary to plot a histogram has been solved -- SUCCESS!!
#          * Meticulously solved and fixed syntax errors and debugging problems -- SUCCESS!!
#          * Forgot to pip install lxml package needed for parsing the xml content from the event's data field in line 65
#          * The app now successfully runs but is not visually clear and has some usability issues.
#          * Imports are sorted for readability and user maintenance purposes.
#          * Fixed datetime format.
#          * Produced histogram on x-axis (timestamps) are visually cluttered together -- it is not clear to read.
#          * The app runs successfully!!

# imports sorted!!
# import modules for use in code---------------------------
import datetime  # uses date and time
import re  # using regex

import matplotlib.pyplot as plt  # many types of graphs and plots
import PySimpleGUI as sg  # a gui for the app so that it is easier to
from evtx import PyEvtxParser  # we use PyEvtxParser to parse events from log
from lxml import etree  # we need lxml to parse data events

# main body-------------------------------------------------
sg.theme("DarkTeal2")  # pysimplegui aesthetic theme
# pysimplegui gui window. includes button to browse for an input.evtx log file and another button to visualise the log
layout = [[sg.Text("1. Input EVTX Log File to Analyse: "), sg.FileBrowse(key="-evtxlogfile-")],
          [sg.Button('2. Visualise the Analysed Log Data')],
          [sg.Button('3. Quit')]]
# creates a window for my app with a title name
window = sg.Window('Security.EVTX Log Analyser', layout, size=(600, 200))


# parseEvtx is defined to extrapolate information from a parsed log file and store it to a dictionary
# the parsed data is extrapolated from the System's EventID and TimeCreated tags in addition to the EventData tags.
def parseEvtx(event):
    sys_tag = event.find("System", event.nsmap)
    event_id = sys_tag.find("EventID", event.nsmap)
    event_ts = sys_tag.find("TimeCreated", event.nsmap)
    event_data = event.find("EventData", event.nsmap)
    r = {}
    r["ts"] = event_ts.values()[0]
    r["eid"] = event_id.text
    for data in event_data.getchildren():
        r[data.attrib["Name"]] = data.text
    return r


# the openEvtxFile function uses the log_folder parameter to open the log file and
# makes log entries for the parsed log using the yield statement.
def openEvtxFile(logs_folder):
    parser = PyEvtxParser(logs_folder)  # added an evtx parser for logs_folder evtx file.
    for record in parser.records():
        yield etree.fromstring(bytes(record['data'], encoding='utf8'))  # parses the data field of an event in xml
        # and returns it to the dictionary encoded in utf-8.


# detectRundll32 checks for new process names in Event ID 4688 and parent process
# name of powershell or cmd storing matching data in a list.
def detectRundll32(logs_folder):
    log_file = openEvtxFile(logs_folder)
    rundll32_logs = []
    for log_entry in log_file:
        try:
            log_data = parseEvtx(log_entry)
            if log_data["eid"] == "4688" and log_data["CommandLine"]:
                if "rundll32" in log_data["NewProcessName"] and re.search("powershell|cmd", log_data["ParentProcessName"]):
                    rundll32_logs.append(log_data)
        except:  # catch exceptions and continue without stopping parsing and analysing the log data regardless
            pass
         
    return rundll32_logs


while True:  # display and interact with the created window using an event loop
    event, values = window.read()
    # event name fixed '3. Quit' instead 'Quit'
    if event == sg.WIN_CLOSED or event == '3. Quit':  # see if the window was closed
        break

    # if the user chooses to visualise the analysed log data then its values = evtxlogfile to parse/analyse log file
    if event == '2. Visualise the Analysed Log Data':
        logs_folder = values["-evtxlogfile-"]
        rundll32_logs = detectRundll32(logs_folder)
        if rundll32_logs:
            # timestamps convert to datetime objects from the rundll32_logs
            # fixed datetime format
            timestamps = [datetime.datetime.strptime(log["ts"], "%Y-%m-%dT%H:%M:%S.%fZ") for log in rundll32_logs]
            # shows in histogram but the timestamp/s are cluttered together -- this needs changing as it is not
            # clear to read
            plt.hist(timestamps, bins='auto', color='#aa0504')  # creates histogram size
            plt.xlabel("Timestamp")
            plt.ylabel("Frequency")
            plt.title("Rundll32 Process Executed w/ PowerShell or CMD Terminal")
            plt.show()
        else:
            sg.Popup("No Rundll32 Processes Executed by Powershell or Cmd Found")

# the end------------------------------------------------
window.close()
