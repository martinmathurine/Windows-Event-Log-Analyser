# README
# Filename: app v2.4.py
# Arbitrary Version: v2.4
# Author: Emanuel Martin Mathurine (w1229113), 6ELEN016W, © University of Westminster, 2022/2023
# LinkedIn: https://www.linkedin.com/in/martinmathurine
# Github: https://github.com/Martin199X
# Description: This is a PySimpleGUI-based Python software tool for processing and visualising selected Windows Event
#              Security.evtx log files.
# Updates: * Revision v2.4.
#          * Added total number of events that meet condition in histogram to be shown in title.
#          * Added more spacing between the histogram's bars if more occurrences are found.
#          * Some non app breaking text typos are corrected and verbiage edited for clarity.
#          * Timestamp labels on the x-axis are visually clearer to read now since I have repositioned the ticks.
#          * The histogram colour was changed to green to match the colour scheme of the software tool aesthetically.
#          * The histogram window created by matplotlib is now larger for visually clarity and readability.
#          * The PySimpleGUI window is now larger to accommodate for visual clarity and aesthetics.
#          * Confirmed to be compatible with older Python3 interpreters [my script is written in Python3].
# Limitations:
#              * With larger log files such as the Securityv2.evtx log file that I supplied it takes longer to process,
#              but, this is expected.
#              * No end-user authentication implemented to provide a layer of security.
#              * The software tool does indeed notify the end-user, however, it would be a nice quality-of-life firmware
#              update if they were emailed or messaged the outcome which may be useful in an enterprise when log files
#              are much larger and could take a considerable amount of time to process. Possibly using Slack's API.

# import modules for use in code---------------------------
import datetime  # working with dates and times
import re  # working with regex

import matplotlib.pyplot as plt  # creating various types of graphs and plots
import PySimpleGUI as sg  # creating a gui for the app for increased usability
from evtx import PyEvtxParser  # parsing and analysing evtx log files
from lxml import etree  # parsing data in events generated from xml content

# main body-------------------------------------------------
sg.theme("DarkTeal2")  # pysimplegui aesthetic theme
# pysimplegui gui window. includes button to browse for an input.evtx log file and another button to visualise the log
layout = [[sg.FileBrowse('Input EVTX', key="-evtxlogfile-", tooltip='Browse for Security.evtx log file')],
          [sg.Button('Analyse Data', tooltip='Draw a histogram from the analysed log data')],
          [sg.Button('Quit', tooltip='Close the software tool')],
          [sg.Text("Author: Emanuel Martin Mathurine (w1229113)")],
          [sg.Text("Institution: (C) University of Westminster, 2022/2023")],
          [sg.Text("Module Code: 6ELEN016W")]]
# creates a window for my app with a title name
window = sg.Window('Network Security Log Analyser v3.0 ', layout, size=(600, 200))


# parseEvtx is defined to extrapolate information from a parsed log file and store it to a dictionary. the parsed data
# is extrapolated from the System's EventID and TimeCreated tags in addition to the EventData tags.
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


# the openEvtxFile function uses the log_folder parameter to open the log file and makes log entries for the parsed log
# using the yield statement.
def openEvtxFile(logs_folder):
    parser = PyEvtxParser(logs_folder)  # added an evtx parser for logs_folder evtx file
    for record in parser.records():
        yield etree.fromstring(bytes(record['data'], encoding='utf8'))  # parses the data field of an event in xml
        # and returns it to the dictionary encoded in utf-8.


# detectRundll32 checks for new process names in Event ID 4688 and parent process name of powershell or cmd storing
# matching data in a list.
def detectRundll32(logs_folder):
    log_file = openEvtxFile(logs_folder)
    rundll32_logs = []
    for log_entry in log_file:
        try:
            log_data = parseEvtx(log_entry)
            if log_data["eid"] == "4688" and log_data["CommandLine"]:
                if "rundll32" in log_data["NewProcessName"] and re.search("powershell|cmd",
                                                                          log_data["ParentProcessName"]):
                    rundll32_logs.append(log_data)
        except:  # catch all exceptions and continue without stopping parsing and analysing the log data regardless
            pass

    return rundll32_logs


# Event loop to process events and get the values of the input then visualises the parsed, analysed and cleaned data
# into a histogram.
while True:  # display and interact with the created window using an event loop
    event, values = window.read()
    # event name fixed 'Quit' instead 'Quit'
    if event == sg.WIN_CLOSED or event == 'Quit':  # if window was closed or uses selects to quit software tool
        break

    # if the user chooses to visualise the analysed log data then its values = evtxlogfile to parse/analyse log file
    if event == 'Analyse Data':
        logs_folder = values["-evtxlogfile-"]
        rundll32_logs = detectRundll32(logs_folder)
        if rundll32_logs:
            # timestamps convert to datetime objects from the rundll32_logs
            timestamps = [datetime.datetime.strptime(log["ts"], "%Y-%m-%dT%H:%M:%S.%fZ") for log in rundll32_logs]
            # fixed datetime format
            fig = plt.figure(figsize=(8, 8))  # change size of matplotlib window that draws histogram
            plt.hist(timestamps, bins='auto', color='#5FD85F', rwidth=0.85)  # creates histogram with clearer spacing
            plt.xlabel("Timestamp")
            plt.ylabel("Frequency")
            plt.title(f"Rundll32 Process Executed with CLI (Event Count={len(timestamps)})")
            # adds total occurances of events that meet condition
            plt.xticks(rotation=20)  # makes the timestamps on the x-axis visually clearer to read
            plt.show()  # creates matplotlib window

        else:
            sg.Popup("No Rundll32 Processes Executed by CLI Found")  # if no conditions are met/cli = powershell or cmd

# the end------------------------------------------------
window.close()
