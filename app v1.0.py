# README
# Filename: app v1.0.py
# Arbitrary Version: v1.0
# Author: Emanuel Martin Mathurine (w1229113), 6ELEN016W, © University of Westminster, 2022/2023
# LinkedIn: https://www.linkedin.com/in/martinmathurine
# Github: https://github.com/Martin199X
# Description: This is a PySimpleGUI-based Python software tool for processing and visualising selected Windows Event
#              Security.evtx log files.
# Updates: * Revision v1.0.
#          * Able to parse and analyse log data successfully.
#          * Issue with getting data from dictionary to plotted bar chart. Visualising the analysed log data failed.
#          * Multiple Python3 syntax errors and debugging problems found -- needs fixing in next revision.
#          * The app does not run.

#----------------------------------------------------------

import os
import Evtx.Evtx as evtx
import datetime
import matplotlib.pyplot as plt
import PySimpleGUI as sg

sg.theme("DarkTeal2")

layout = [[sg.Text("Input EVTX Log File to Analyse: "), sg.FileBrowse(key="-evtxlogfile-")],
          [sg.Button('Visualise the Analysed Log Data'), sg.Button('Save Results')],
          [sg.Text(size=(50, 1), key="-save-")]]


window = sg.Window('Network Security Log Analyser', layout, size=(600,200))

while True:
    event, values = window.read()
    if event == sg.WINDOW_CLOSED:
        break
    if event == 'Visualise the Analysed Log Data':
        logs_folder = values["-evtxlogfile-"]
        detectRundll32(logs_folder)

window.close()


#declares a log_folder parameter -- a folder path for parsing and analysing the Security.extx logfile line-by-line.
logs_folder = r"C:\Users\marti\Desktop\Coursework\logs"

#parseEvtx is defined to extrapolate information from a parsed log file and then save that to a dictionary.
#the parsed data is extrapolated from the System tag and within that tag the EventID and TimeCreated tags in addition to the EventData.
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

#the openEvtxFile function uses the log_folder parameter to open the log file and makes log entries for the parsed log using the yield statement.
def openEvtxFile(logs_folder):
    with evtx.Evtx(logs_folder) as log_file:
        for log_entry in log_file.records():
            yield log_entry.lxml()

#detectRundll32 parses the log entries to identify whether the Event ID 4688 contains a new process name in rundll32 as well as powershell or cmd in the parent process name within the log's parsed data.
#catch errors and continue without stopping parsing and analysing the log data regardless
def detectRundll32(logs_folder):
    log_file = openEvtxFile(logs_folder)
    for log_entry in log_file:
        try:
            log_data = parseEvtx(log_entry)
            if log_data["eid"] == "4688" and log_data["CommandLine"]:
                if "rundll32" in log_data["NewProcessName"] and re.search("powershell|cmd", log_data["ParentProcessName"]):
                    print(log_data["CommandLine"])
        except:
            pass

#creates and displays a plotted bar chart to visualise the analysed data on the x-axis.
def plotBarChart(events, users):
    plt.subplot(211)
    plt.bar(range(len(events)), list(events.values()), align="center")
    plt.xticks(range(len(events)), list(events.keys()))
    plt.subplot(212)
    plt.bar(range(len(users)), list(users.values()), align="center")
    plt.xticks(range(len(users)), list(users.keys()))
    plt.show()







































