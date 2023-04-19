# README
# Filename: app v2.0.py
# Arbitrary Version: v2.0
# Author: Emanuel Martin Mathurine (w1229113), 6ELEN016W, © University of Westminster, 2022/2023
# LinkedIn: https://www.linkedin.com/in/martinmathurine
# Github: https://github.com/Martin199X
# Description: This is a PySimpleGUI-based Python software tool for processing and visualising selected Windows Event
#              Security.evtx log files.
# Updates: * Revision v2.0.
#          * Replaced the broken bar chart function from revision 1.0 now with a while loop to instead draw a histogram.
#          * Issue with getting data from dictionary to plot a histogram. Visualising the analysed data failed.
#          * Multiple Python3 syntax errors and debugging problems found -- needs fixing.
#          * Suspected issue with imported evtx parser. Will try others through trial and error to find one that works.
#          * The app does not run.

#import modules for use in code----------------------------
import Evtx.Evtx as evtx #parsing and analysing windows event security .evtx log files 
import matplotlib.pyplot as plt #many types of graphs and plots
import PySimpleGUI as sg #a gui for the app so that it is easier to use
import os #selecting folder/file path
import re #using regex
import datetime #uses date and time

#main body-------------------------------------------------
sg.theme("DarkTeal2") #pysimplegui aesthetic theme

layout = [[sg.Text("1. Input EVTX Log File to Analyse: "), sg.FileBrowse(key="-evtxlogfile-")], #pysimplegui layout structure. includes a file browse button to find input .evtx log file, another button to visualise the analysed log data and a third button to save the results 
          [sg.Button('2. Visualise the Analysed Log Data'), sg.Button('3. Save Results')],
          [sg.Text(size=(40, 1), key="-save-")],
          [sg.Button('Quit')]

window = sg.Window('Network Security Log Analyser', layout, size=(600,200)) #creates a window for my app with a title name

def parseEvtx(event): #parseEvtx is defined to extrapolate information from a parsed log file and then save that to a dictionary. the parsed data is extrapolated from the System tag and within that tag the EventID and TimeCreated tags in addition to the EventData.
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

def openEvtxFile(logs_folder): #the openEvtxFile function uses the log_folder parameter to open the log file and makes log entries for the parsed log using the yield statement.
    with evtx.Evtx(logs_folder) as log_file:
        for log_entry in log_file.records():
            yield log_entry.lxml()

def detectRundll32(logs_folder): #detectRundll32 parses the log entries in an array to identify whether the Event ID 4688 contains a new process name in the rundll32 process, powershell or cmd in the parent process name within the log's parsed data and then stores the matching data in a list.
    log_file = openEvtxFile(logs_folder)
    rundll32_logs = []
    for log_entry in log_file:
        try:
            log_data = parseEvtx(log_entry)
            if log_data["eid"] == "4688" and log_data["CommandLine"]:
                if "rundll32" in log_data["NewProcessName"] and re.search("powershell|cmd", log_data["ParentProcessName"]):
                    rundll32_logs.append(log_data)
        except: #catch errors and continue without stopping parsing and analysing the log data regardless
            pass
    return rundll32_logs

while True:#display and interact with the created window using an event loop
    event, values = window.read()
    if event == sg.WIN_CLOSED or event == 'Quit': #see if the window was closed
        break
    if event == '2. Visualise the Analysed Log Data': #if the user selects '2. Visualise the Analysed Log Data' the log data is then equal to the values of -evtxlogfile- which is used for parsing and analysing the log data
        logs_folder = values["-evtxlogfile-"]
        rundll32_logs = detectRundll32(logs_folder)
        if rundll32_logs:
            timestamps = [datetime.datetime.strptime(log["ts"], "%Y-%m-%d %H:%M:%S") for log in rundll32_logs] #timestamps convert to datetime objects from the rundll32_logs
            plt.hist(timestamps, bins='auto') #the histogram size is set to auto so that the algorithm automatically determines the most ideal distribution of the data
            plt.xlabel("Timestamp") #timestamp
            plt.ylabel("Rundll32 Process Frequency")
            plt.title("Rundll32 Process Executed by PowerShell or CMD")
            plt.show()
        else:
            sg.Popup("No Rundll32 Processes Executed by Powershell or Cmd Found")

#the end------------------------------------------------
window.close()