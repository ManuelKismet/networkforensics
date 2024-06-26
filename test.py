# import win32evtlog
# import win32con
# import re
#
#
# def get_forensic_logs(server, logtype):
#     server = 'localhost'
#     logtype = 'Security'
#     hand = win32evtlog.OpenEventLog(server, logtype)
#     flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
#     forensic_data = []
#
#     try:
#         while True:
#             events = win32evtlog.ReadEventLog(hand, flags, 0)
#             if not events:
#                 break
#             for event in events:
#                 if event.EventID in [4663, 4688, 5156, 4104]:  # Handling multiple event types
#                     event_info = {
#                         "Time Generated": event.TimeGenerated.strftime('%Y-%m-%d %H:%M:%S'),
#                         "Event ID": event.EventID,
#                         "Source": event.SourceName,
#                         "Category": event.EventCategory,
#                         "Strings": event.StringInserts,
#                         "Computer": event.ComputerName
#                     }
#                     forensic_data.append(event_info)
#     finally:
#         win32evtlog.CloseEventLog(hand)
#
#     return forensic_data
#
#
# def analyze_powershell_script(script_text):
#     # Look for common malicious patterns
#     patterns = ['Invoke-Mimikatz', 'Invoke-Shellcode', 'DownloadString', 'Net.WebClient', 'Start-Process']
#     findings = [pattern for pattern in patterns if re.search(pattern, script_text, re.IGNORECASE)]
#     return findings
#
#
# def parse_details(strings, event_id):
#     if event_id == 4663:
#         return {
#             "Object Name": strings[5],
#             "Access Mask": strings[6],
#             "Process Name": strings[8]
#         }
#     elif event_id == 4688:
#         return {
#             "New Process Name": strings[4],
#             "Creator Process Name": strings[8],
#             "Process Command Line": strings[9] if len(strings) > 9 else "Not Available"
#         }
#     elif event_id == 5156:
#         return {
#             "Source IP": strings[2],
#             "Source Port": strings[3],
#             "Dest IP": strings[4],
#             "Dest Port": strings[5],
#             "Protocol": strings[6]
#         }
#     elif event_id == 4104:
#         findings = analyze_powershell_script(strings[1]) if len(strings) > 1 else []
#         return {
#             "Script Block Text": strings[1] if len(strings) > 1 else "No Script Available",
#             "User": strings[0],
#             "Potential Malicious Activities": findings
#         }
#     return {}
#
#
# def forensic_data(data):
#     all_entries = []
#     for entry in data:
#         details = parse_details(entry["Strings"], entry["Event ID"])
#         detail_entries = []
#         for key, value in details.items():
#             detail_entries.append({key: value})
#         log_evidence = {
#             "Time Generated": entry["Time Generated"],
#             "Event ID": entry["Event ID"],
#             "Source": entry["Source"],
#             "Category": entry["Category"],
#             "Computer": entry["Computer"],
#             "Details": detail_entries
#         }
#         all_entries.append(log_evidence)
#     return all_entries
