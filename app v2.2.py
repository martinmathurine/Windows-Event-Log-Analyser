# README
# Filename: app v2.2.py
# Arbitrary Version: v2.2
# Author: Emanuel Martin Mathurine (w1229113), 6ELEN016W, ©  University of Westminster, 2022/2023
# LinkedIn: https://www.linkedin.com/in/martinmathurine
# Github: https://github.com/Martin199X
# Description: This is a PySimpleGUI-based Python software tool for processing and visualising selected Windows Event
#              Security.evtx log files.
# Updates: * Revision v2.2.
#          * Used evtx parser again from revision 2.0 -- no success running the app. Possibly a configuration issue?
#          * Issue with getting data from dictionary to plot a histogram. Visualising the analysed data failed.
#          * Multiple Python3 syntax errors and debugging problems found -- needs fixing.
#          * Suspected issue with imported evtx parser. Will try others through trial and error to find one that works.
#          * Edited the PySimpleGUI code block to better reflect how I want the software tool to be used.
#          * The app still does not run.

# import modules for use in code----------------------------
import Evtx.Evtx as evtx  # parsing and analysing windows event security .evtx log files
import matplotlib.pyplot as plt  # many types of graphs and plots
import PySimpleGUI as sg  # a gui for the app so that it is easier to use
import re  # using regex
import datetime  # for use with date and time values

# main body-------------------------------------------------
sg.theme("DarkTeal2")  # pysimplegui aesthetic theme
# pysimplegui gui window. includes button to browse for an input.evtx log file and another button to visualise the log
layout = [[sg.Text("Input EVTX Log File to Analyse: "), sg.FileBrowse(key="-evtxlogfile-")],
          [sg.Button('2. Visualise the Analysed Log Data')],
          [sg.Button('Quit')]]
# creates a window for my app with a title name
window = sg.Window('Network Security Log Analyser', layout, size=(600, 200))


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
    with evtx.Evtx(logs_folder) as log_file:
        for log_entry in log_file.records():
            yield log_entry.lxml()


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
    if event == sg.WIN_CLOSED or event == 'Quit':  # see if the window was closed
        break

    # if the user chooses to visualise the analysed log data then its values = evtxlogfile to parse/analyse log file
    if event == '2. Visualise the Analysed Log Data':
        logs_folder = values["-evtxlogfile-"]
        rundll32_logs = detectRundll32(logs_folder)
        if rundll32_logs:
            # timestamps convert to datetime objects from the rundll32_logs
            timestamps = [datetime.datetime.strptime(log["ts"], "%Y-%m-%d %H:%M:%S") for log in rundll32_logs]
            plt.hist(timestamps, bins='auto', color='#aa0504')  # creates histogram size
            plt.xlabel("Timestamp")
            plt.ylabel("Frequency")
            plt.title("Rundll32 Process Executed w/ PowerShell or CMD Terminal")
            plt.show()
        else:
            sg.Popup("No Rundll32 Processes Executed by Powershell or Cmd Found")

# the end------------------------------------------------
window.close()
