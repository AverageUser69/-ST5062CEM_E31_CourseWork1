# Importing required libraries and modules
# for interacting with operating system
import os
#for string manipulation and pattern matching
import re
# for time-related functions
import time
# for hashing functions such as md5
import hashlib
# for handling dates and times
import datetime
# for creating graphical user interfaces
import tkinter as tk
#for more modern-looking widgets for tkinter
from tkinter import ttk
#for accessing file dialog boxes in tkinter
from tkinter import filedialog
#for handling images in tkinter
from tkinter import PhotoImage\
# for showing message boxes in tkinter
import tkinter.messagebox as messagebox
'''============================================================ DELETE FILE CODE ============================================================'''
def delete_file(file):
    # remove the specified file
    os.remove(file)
    # print the file name for confirmation
    print (file)
    # store the contents of the temp.txt file into the lines list
    lines = []
    with open("temp.txt", "r") as f:
        lines = f.readlines()
    # write the contents of the lines list back to temp.txt, excluding the line that contains the specified file
    with open("temp.txt", "w") as f:
        for line in lines:
            if file not in line:
                f.write(line)
            else:
                continue
    # call the show_logs_frame function to update the logs
    show_logs_frame()
'''============================================================ IGNORE FILE CODE ============================================================'''
def ignore_file(file):
    # print the file name for confirmation
    print (file)
    # store the contents of the temp.txt file into the lines list
    lines = []
    with open("temp.txt", "r") as f:
        lines = f.readlines()
    # write the contents of the lines list back to temp.txt, excluding the line that contains the specified file
    with open("temp.txt", "w") as f:
        for line in lines:
            if file not in line:
                f.write(line)
            else:
                continue
    # append the specified file name to the ignored.txt file
    with open("ignored.txt", "a") as ignored_file:
        ignored_file.write(file + "\n")
    # destroy all widgets in the logs_frame and call the show_logs_frame function to update the logs
    for widget in logs_frame.winfo_children():
        widget.destroy()
    print("done")
    show_logs_frame()
    print(file)
'''======================================================= LIST THE SUSPICIOUS FILE CODE ======================================================='''    
def open_temp_file():
    # Open the temp.txt file and read the contents into the lines list
    with open("temp.txt", "r") as f:
        lines = f.readlines()      
    # Counter for keeping track of the current row
    row_counter = 1
    # Loop through each line in the lines list
    for line in lines:
        # Evaluate the line to turn it into a dictionary
        data = eval(line)
        # Initialize lists and variables for storing relevant information
        true_results = []
        file = None
        result = None
        # Loop through the items in the data dictionary
        for d in data:
            # Check if the "Suspicious extention" key is present and its value is True
            if "Suspicious extention" in d and d["Suspicious extention"]:
                true_results.append("Suspicious extention")
            # Check if the "Contain system call functions" key is present and its value is True
            if "Contain system call functions" in d and d["Contain system call functions"]:
                true_results.append("Contain system call functions")
            # Check if the "Contain IP address or URL" key is present and its value is True
            if "Contain IP address or URL" in d and d["Contain IP address or URL"]:
                true_results.append("Contain IP address or URL")
            # Check if the "Is a malware" key is present and its value is True
            if "Is a malware" in d and d["Is a malware"]:
                true_results.append("Is a malware")
            # Check if the "file" key is present
            if "file" in d:
                file = d["file"]
            # Check if the "result" key is present
            if "result" in d:
                result = d["result"]
# Display the file and result label in the logs_frame 
        if true_results:
            # Display the file name
            file_label = ttk.Label(logs_frame, text="File: " + str(file) + " ", 
                                font=("Helvetica",11), foreground="white", background="#0377a8")
            file_label.grid(row=row_counter, column=1,columnspan=4, sticky="ws",pady=0)  
            # Display the result label
            result_label = ttk.Label(logs_frame, text="Result: " + str(result) + " ", 
                    font=("Helvetica",11), foreground="red", background="#0377a8")
            result_label.grid(row=row_counter, column=1,columnspan=4,pady=5, sticky="w")
            # Display the buttons based on the result
            # If the result is potential threat
            if result == "potential threat":
                # Display the ignore button
                ignore_button = tk.Button(logs_frame, text="Ignore", font=("Helvetica", 10),
                                          command=lambda file=file:ignore_file(file),
                            background="#118fb0", foreground="#b4fadc", relief="raised",
                            activebackground="#144552", activeforeground="white",height=1)      
                ignore_button.grid(row=row_counter, column=6, pady=(5, 5), padx=(5, 5), sticky="se")
                ignore_button.config(width=8)
                # Display the delete button
                delete_button = tk.Button(logs_frame, text="Delete", font=("Helvetica", 10),
                                          command=lambda file=file:delete_file(file),
                            background="#118fb0", foreground="#b4fadc", relief="raised",
                            activebackground="#144552", activeforeground="red",height=1)      
                delete_button.grid(row=row_counter, column=5, pady=(5, 5), padx=(5, 5), sticky="se")
                delete_button.config(width=8)
            # If the result is a virus
            elif result == "virus":
                # Display the delete button
                delete_button = tk.Button(logs_frame, text="Delete",command=lambda 
                            file=file:delete_file(file), font=("Helvetica", 10),
                            background="#118fb0", foreground="#b4fadc", relief="raised",
                            activebackground="#144552", activeforeground="red",height=1)      
                delete_button.grid(row=row_counter, column=5, pady=(5,5), padx=(5, 5), sticky="se")
                delete_button.config(width=8)
            # Increment the row_counter for the next row
            row_counter += 1
'''======================================================= WINDOWS AND FRAMES CODE =======================================================''' 
# Create the root window
root = tk.Tk()

# Set the window size to 800x600 and update the idle tasks
root.geometry("800x600")
root.update_idletasks()

# Calculate the x and y coordinates to center the window
x = (root.winfo_screenwidth() - root.winfo_reqwidth()) / 4
y = (root.winfo_screenheight() - root.winfo_reqheight()) / 6

# Set the window position to the calculated x and y
root.geometry("+%d+%d" % (x, y))

# Set the window title
root.title("Simple Anti-virus")

# Create the scan frame, logs frame, and main frame
scan_frame = tk.Frame(root, bg="#0377a8", width=800, height=600, name="scan_frame")
logs_frame = tk.Frame(root, bg="#0377a8", width=800, height=800, name="logs_frame")
logs_frame.config(width=800, height=800)
main_frame = tk.Frame(root, bg="#0377a8", width=800, height=600, name="main_frame")

# Function to display the scan frame
def show_scan_frame():
    # Hide the main frame
    main_frame.grid_forget()
    # Show the scan frame
    scan_frame.grid(row=0, column=0)
    # Set the size of the rows and columns in the scan frame
    for i in range(10):
        scan_frame.rowconfigure(i, minsize=60)
    for i in range(10):
        scan_frame.columnconfigure(i, minsize=80)

# Function to display the logs frame
def show_logs_frame():
    # Hide the main frame
    main_frame.grid_forget()
    # Show the logs frame
    logs_frame.grid(row=0, column=0)
    # Set the size of the rows and columns in the logs frame
    for i in range(15):
        logs_frame.rowconfigure(i, minsize=60)
    for i in range(15):
        logs_frame.columnconfigure(i, minsize=80)
    
    # Create the text for the "Scan Logs" label
    system_logs_text = ttk.Label(logs_frame, text="Scan Logs", 
                      font=("Travelast",20), foreground="#b4fadc", background="#0377a8")
    # Show the "Scan Logs" label in the logs frame
    system_logs_text.grid(row=0, column=4, pady=(10,5), padx=30)
    
    # Create the text for the divider line
    # Add divider text to logs frame
    divider_text = ttk.Label(logs_frame, text="=========================================================================================", 
                            font=("Travelast",20), foreground="#b4fadc", background="#0377a8")
    divider_text.grid(row=1, column=0, pady=(10,50), padx=0,sticky="nw",columnspan=12)

    # Add date text to logs frame
    log_frame_date_text = ttk.Label(logs_frame, text=f"{today}", 
                            font=("Helvetica",12), foreground="white", background="#0377a8")
    log_frame_date_text.grid(row=0, column=7,sticky="w",padx=(10))

    # Add back button to logs frame
    back_button = tk.Button(logs_frame, text="Back", command=back_to_main, font=("Helvetica", 12), 
                            background="#118fb0", foreground="#b4fadc", relief="raised", bd=3, 
                            activebackground="#144552",activeforeground="red")
    back_button.grid(row=8, column=0,pady=(50,5),padx=(15,10), sticky="w")
    back_button.config(width=8)

    # Add open log button to logs frame
    open_log_button = tk.Button(logs_frame, text="Open Log", command=open_log_file, 
                                    font=("Helvetica", 12),background="#118fb0", foreground="#b4fadc", 
                                    relief="raised",activebackground="#144552", activeforeground="red",bd=3)
    open_log_button.grid(row=8, column=7, pady=(50, 5), padx=(15, 10), sticky="w")
    open_log_button.config(width=8)

    # function to open a temporary file
    open_temp_file()
        
def scan_logs_frame():
    # forget the grid configuration of scan_frame and set the grid configuration of logs_frame
    scan_frame.grid_forget()
    logs_frame.grid(row=0, column=0)

    # set the row size to 60 for 15 rows
    for i in range(15):
        logs_frame.rowconfigure(i, minsize=60)

    # set the column size to 80 for 15 columns
    for i in range(15):
        logs_frame.columnconfigure(i, minsize=80)

    # call the open_temp_file function
    open_temp_file()

def back_to_main():
    # forget the grid configurations of scan_frame and logs_frame and set the grid configuration of main_frame
    scan_frame.grid_forget()
    logs_frame.grid_forget()
    main_frame.grid(row=0, column=0)

    # set the row size to 60 for 10 rows
    for i in range(10):
        main_frame.rowconfigure(i, minsize=60)

    # set the column size to 80 for 10 columns
    for i in range(10):
        main_frame.columnconfigure(i, minsize=80)

# set the grid configuration of main_frame
main_frame.grid(row=0, column=0)

# set the row size to 60 for 10 rows
for i in range(10):
    main_frame.rowconfigure(i, minsize=60)

# set the column size to 80 for 10 columns
for i in range(10):
    main_frame.columnconfigure(i, minsize=80)

'''======================================================= OPEN LOG FILE CODE =======================================================''' 
# Display log file in a new window
selected_folder = None
def open_log_file():
    # Create a new Toplevel window
    log_file_frame = tk.Toplevel(main_frame)
    # Set window geometry
    log_file_frame.geometry("950x725+{}+{}".format(int(root.winfo_screenwidth() / 2 - 400), int(root.winfo_screenheight() / 2 - 400)))
    # Set background color
    log_file_frame.config(bg='white')
    # Set window title
    log_file_frame.title("Log File")

    # Display log file in a Text widget
    log_file_text = tk.Text(log_file_frame, bg='white', fg='black', font=("Helvetica", 12),
                            wrap=tk.WORD, height=35, width=100)
    log_file_text.grid(row=0, column=0, padx=10, pady=10)
    # Add scrollbar to the Text widget
    log_file_scrollbar = tk.Scrollbar(log_file_frame, orient="vertical", command=log_file_text.yview)
    log_file_scrollbar.grid(row=0, column=1, sticky="ns")
    log_file_text["yscrollcommand"] = log_file_scrollbar.set

    # Add search entry widget
    search_entry = ttk.Entry(log_file_frame, width=20, font=("Helvetica", 19), 
                            foreground="#03045e", style="Round.TEntry", justify='center')
    search_entry.grid(row=1, column=0, padx=50, pady=10,sticky='w')

    # Add Search button
    back_button = tk.Button(log_file_frame, text="Search",
                            command=lambda: highlight_search_text(log_file_text, search_entry.get()), 
                            font=("Helvetica", 13), background="#00b4d8", 
                        foreground="#03045e", relief="raised", bd=3, activebackground="#144552",activeforeground="#1985a1")
    back_button.grid(row=1, column=0, pady=10,padx=50)
    back_button.config(width=15)

    # Add Clear button
    back_button = tk.Button(log_file_frame, text="Clear",
                             command=lambda: clear_search(log_file_text), 
                            font=("Helvetica", 13), background="#00b4d8", 
                        foreground="#03045e", relief="raised", bd=3, activebackground="#144552",activeforeground="#1985a1")
    back_button.grid(row=1, column=0, pady=10,sticky='e',padx=(0,100))
    back_button.config(width=15)


    # open the log.txt file
    with open("log.txt") as f:
        # read all the lines in the file
        lines = f.readlines()

    # iterate over each line in the lines list
    for i, line in enumerate(lines):
        # if the index is even
        if i % 2 == 0:
            # insert the line into log_file_text widget with black foreground color
            log_file_text.insert(tk.END, line, 'black_fg')
        else:
            # insert the line into log_file_text widget with purple foreground color
            log_file_text.insert(tk.END, line, 'purple_fg')

    # set the tag configuration for the 'black_fg' tag with black foreground color and font
    log_file_text.tag_config('black_fg', foreground='black', font=("Helvetica", 11))

    # set the tag configuration for the 'purple_fg' tag with purple foreground color and font
    log_file_text.tag_config('purple_fg', foreground='purple', font=("Helvetica", 11))

    # set the tag configuration for the 'highlight' tag with yellow background color
    log_file_text.tag_config('highlight', background='yellow')

    # disable the editing of the log_file_text widget
    log_file_text.config(state=tk.DISABLED)

    # move the view to the end of the log_file_text widget
    log_file_text.yview(tk.END)

    '''======================================================= HIGHLIGHT SEARCH CODE =======================================================''' 
    def highlight_search_text(text_widget, search_text):
        # Check if the search text is not blank
        if not search_text:
            # Display an error message if the search text is blank
            messagebox.showinfo("Search Result", "Search cannot be blank", parent=log_file_frame)
            return

        # Enable editing of the text widget
        text_widget.config(state=tk.NORMAL)

        # Start the search from the beginning of the text
        start_index = "1.0"
        found = False

        # Search for the text in the widget
        while True:
            # Search for the text using the start index and end index of the widget
            start_index = text_widget.search(search_text, start_index, stopindex=tk.END)
            # Break the loop if the text is not found
            if not start_index:
                break
            # Set found to True if the text is found
            found = True
            # Calculate the end index of the text
            end_index = f"{start_index}+{len(search_text)}c"
            # Add a highlight tag to the text
            text_widget.tag_add('highlight', start_index, end_index)
            # Set the start index for the next search to the end index
            start_index = end_index

        # Disable editing of the text widget
        text_widget.config(state=tk.DISABLED)

        # Show an info message if the text is not found
        if not found:
            messagebox.showinfo("Search Result", "No results found", parent=log_file_frame)

    def clear_search(log_file_text):
        # Remove the highlight tag from the text widget
        log_file_text.tag_remove("highlight", "1.0", tk.END) 
'''======================================================= SELECT FOLDER CODE =======================================================''' 
def browse_folder():
    global selected_folder
    folder_path = filedialog.askdirectory()
    if not folder_path:
        messagebox.showerror("Error", "No folder selected")
        return
    selected_folder = os.path.normpath(folder_path)
    files = os.listdir(folder_path)
    project_text = ttk.Entry(scan_frame, font=("Helvetica",11), foreground="black", background="#0377a8",width=45)
    project_text.insert(0, folder_path)
    project_text.grid(row=1, column=1,sticky="w", pady=10, padx=5, columnspan=4)
    project_text.config(state="readonly", background="#0377a8")
    
def check_for_possible_threats():
    # print ("Printed")
    results=[]
    global selected_folder
    with open("temp.txt", "w") as temp_file:
        temp_file.write("")
    
    def check_file(file_path):
        # Open the file "extensions.txt" in read mode
        with open("extensions.txt", "r") as f:
            # Create a list of extensions by reading each line of the file and removing any whitespaces
            extensions = [line.strip() for line in f.readlines()]

        # Get the file extension of the file_path
        file_extension = file_path.split(".")[-1]

        # Check if the file extension is not in the list of extensions
        if file_extension not in extensions:
            result = {}
            # Set the value of "Normal extention" to False in the result dictionary
            result['Normal extention'] = False
            # Return the result dictionary
            return result
        else:
            # Configure the state of the output_field widget to "normal"
            output_field.config(state="normal")
            # Create a text frame with padding and background color
            text_frame = tk.Frame(output_field, padx=10, pady=5, background="#dee2e6")
            # Create a label with text, background color and foreground color
            text = tk.Label(text_frame, text= file_path + " Has suspicious extention.", 
                            background="#dee2e6",foreground="red")
            # Pack the text into the text frame
            text.pack()
            # Insert the text frame into the end of the output_field widget
            output_field.window_create("end", window=text_frame)
            # Update the output_field widget
            output_field.update()
            result = {}
            # Set the value of "Suspicious extention" to True in the result dictionary
            result['Suspicious extention'] = True
            # Return the result dictionary
            return result
    '''===================================================== SYSTEM CALL CHECK CODE =====================================================''' 
    def check_content(file_path):
        # Initialize a dictionary to store the result
        result = {} 
        # Open the file "terms.txt" and read the list of terms to be searched for
        with open("terms.txt", "r") as f:
            terms = [line.strip() for line in f.readlines()]   
        # Open the file provided as an argument and check if any of the terms are in the file
        with open(file_path, "r") as f:
            for line in f.readlines():
                for term in terms:
                    if term in line:
                        # Configure the output field to allow updates
                        output_field.config(state="normal")
                        # Create a frame for the output text
                        text_frame = tk.Frame(output_field, padx=10, pady=5, background="#dee2e6")
                        # Create a label with the output text
                        text = tk.Label(text_frame, text= file_path + " Contain system call functions.",
                                        background="#dee2e6",foreground="red")
                        text.pack()
                        # Insert the frame into the output field
                        output_field.window_create("end", window=text_frame)
                        # Update the output field to display the new text
                        output_field.update()

                        # Update the result dictionary with the findings
                        result['Contain system call functions'] = True
                        # Return the result
                        return result
                    else:
                        # Update the result dictionary with the findings
                        result = {}
                        result['Contain system call functions'] = False
                        # Return the result
                        return result
        # Return the result
        return result
    '''====================================================== IP/URL CHECK CODE ======================================================''' 
    def contains_ip_or_url(filename):
        # Open the file for reading
        with open(filename, 'r') as f:
            code = f.read()

        # Define regular expressions for IP addresses and URLs
        ip_regex = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
        url_regex = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'

        # Check if the code contains an IP address or a URL
        if re.search(ip_regex, code) or re.search(url_regex, code):
            # Display a message indicating that the file contains an IP address or a URL
            output_field.config(state="normal")
            text_frame = tk.Frame(output_field, padx=10, pady=5, background="#dee2e6")
            text = tk.Label(text_frame, text= filename + " Contain an IP address or URL.", background="#dee2e6",foreground="red")
            text.pack()
            output_field.window_create("end", window=text_frame)
            output_field.update()
            
            # Return a dictionary indicating that the file contains an IP address or a URL
            result = {}
            result['Contain IP address or URL'] = True
            return result
        else:
            # Return a dictionary indicating that the file does not contain an IP address or a URL
            result = {}
            result['Contain IP address or URL'] = False
            return result
    '''======================================================= MD5 CHECK CODE =======================================================''' 
    def get_file_md5(file_path):
        # Open the file and read its contents
        with open(file_path, 'rb') as file:
            contents = file.read()
        # Calculate the md5 hash of the file contents
        return hashlib.md5(contents).hexdigest()

    def compare_md5(file_md5, hash_list):
        # Check if the file's md5 hash is in the list of hashes
        return file_md5 in hash_list

    def check_file_md5(file_path):
        # Path to the file that contains a list of hashes
        hash_list_file = "lines.txt"
        # Get the md5 hash of the file
        file_md5 = get_file_md5(file_path)
        # Read the list of hashes from the file
        with open(hash_list_file, 'r') as f:
            hash_list = [line.strip() for line in f.readlines()]
        # Check if the file's md5 hash is in the list of hashes
        is_match = compare_md5(file_md5, hash_list)
        # If the file's hash is in the list, it's a malware
        if is_match:
            # Update the output field
            output_field.config(state="normal")
            text_frame = tk.Frame(output_field, padx=10, pady=5, background="#dee2e6")
            text = tk.Label(text_frame, text= file_path + " Is a Malware.", background="#dee2e6",foreground="red")
            text.pack()
            output_field.window_create("end", window=text_frame)
            output_field.update()
            # Return the result
            result = {}
            result['Is a malware'] = True
            return result
        else:
            # Return the result if the file's hash is not in the list
            result = {}
            result['Is a malware'] = False
            return result

    '''======================================================= SCAN PROCESS CODE =======================================================''' 
    def process_file(file):
        # Perform scan for file extension
        result_for_extension_scan = check_file(file)
        # Perform scan for file content
        result_for_content_check = check_content(file)
        # Check if file contains IP addresses or URLs
        result_for_ip_and_url = contains_ip_or_url(file)
        # Check the file's MD5 hash
        result_for_md5_check = check_file_md5(file)
        # Store the final results in a dictionary
        final_result = {}
        # Combine the results of the individual scans
        results = [result_for_extension_scan, result_for_content_check, result_for_ip_and_url, result_for_md5_check]
        # Iterate through the results to see if any of them indicate that the file is a threat
        for result in results:
            for key, value in result.items():
                if value:
                    final_result[key] = True
        # Classify the file as a virus, potential threat, or ignored based on the results
        if 'Is a malware' in final_result and final_result['Is a malware'] == True:
            results.append({"file": file, "result": "virus"})
        elif any(result in final_result for result in ['Suspicious extention', 'Contain IP address or URL', 'Contain system call functions']):
            results.append({"file": file, "result": "potential threat"})
        else:
            results.append({"file": file, "result": "ignored"})
        # Write the results to a log file
        with open("log.txt", "a") as log_file:
            results = str(results).replace("\\\\", "/")
            log_file.write(f"[{datetime.datetime.now()}]: {results}\n")
        # Write the results to a temporary file
        with open("temp.txt", "a") as temp_file:
            temp_file.write(str(results)+"\n")
    '''===================================================== UPDATE OUTPUT CODE =====================================================''' 
    def update_output_field(directory, index, files):
        # Exit the function if we have processed all of the files
        if index == len(files):
            return
        # Replace backslashes in the directory path with forward slashes
        directory = str(directory).replace("\\", "/")
        # Construct the full path of the current file
        file = os.path.join(directory, files[index]).replace("\\", "/")
        # Check if the file has already been processed
        with open("ignored.txt", "r") as f:
            contents = f.read()
            if file in contents:
                # If the file has already been processed, move on to the next file
                root.after(100, update_output_field, directory, index + 1, files)
                return
        # Enable editing of the output field
        output_field.config(state="normal")
        # Create a new frame for the file being processed
        text_frame = tk.Frame(output_field, padx=10, pady=5, background="#dee2e6")
        # Create a label for the file being processed
        text = tk.Label(text_frame, text="Scanning " + file, background="#dee2e6")
        text.pack()
        # Add the label to the output field
        output_field.window_create("end", window=text_frame)
        output_field.update()
        # Scan the file using the process_file function
        process_file(file)
        # Move on to the next file after a 100ms delay
        root.after(100, update_output_field, directory, index + 1, files)

    def scan_logs_frame():
        # hide scan frame and show logs frame
        scan_frame.grid_forget()
        logs_frame.grid(row=0, column=0)

        # configure rows and columns size for the logs frame
        for i in range(10):
            logs_frame.rowconfigure(i, minsize=60)
        for i in range(10):
            logs_frame.columnconfigure(i, minsize=80)
        
        # open and read the contents of the temporary log file
        open_temp_file()

    def view_report_messagebox():
        # ask the user if they want to view the report
        result = messagebox.askyesno("View Report", "Do you want to view the report?")
        if result == True:
            # if the user confirms, show the scan logs frame
            scan_logs_frame()

    def main(directory):
        # scan the selected folder for potential threats
        for root, dirs, files in os.walk(directory):
            update_output_field(root, 0, files)
    main(selected_folder)
    # wait for 6 seconds
    time.sleep(6)

    # show the message box asking if the user wants to view the report
    view_report_messagebox()

    
now = datetime.datetime.now()
today = now.strftime("%d/%m/%Y")
def scan_file():
    global selected_folder
    if selected_folder:
         print(selected_folder)
    else:
        print("No folder selected")
#==================================================================================================#   
#======================================== Main Frame Texts ========================================#
#==================================================================================================#
original_image = PhotoImage(file="virus.png", height=500, width=500)
image = original_image.subsample(6, 6)
virus_image = ttk.Label(main_frame, image=image, background="#0377a8")
virus_image.grid(row=0, column=1,sticky="e")

project_text = ttk.Label(main_frame, text="SIMPLE ANTI-VIRUS", font=("Mexcellent", 40), foreground="#b4fadc", background="#0377a8")
project_text.grid(row=0, column=2, pady=(20,20), padx=(10,20))

by_text = ttk.Label(main_frame, text="by", font=("Hanging Letters", 40), foreground="#b4fadc", background="#0377a8")
by_text.grid(row=1, column=2, pady=10, padx=10)

name_text = ttk.Label(main_frame, text="Subodh Ghimire", font=("3x5", 40), foreground="#b4fadc", background="#0377a8")
name_text.grid(row=2, column=2, pady=(10,10), padx=10 ,sticky='n')

#==================================================================================================#   
#======================================= Main Frame Buttons =======================================#
#==================================================================================================#

back_button = tk.Button(main_frame, text="Start Scanning", command=show_scan_frame, font=("Helvetica", 13), background="#118fb0", 
                        foreground="#b4fadc", relief="raised", bd=3, activebackground="#144552",activeforeground="#1985a1")
back_button.grid(row=3, column=2, pady=10)
back_button.config(width=15)


back_button = tk.Button(main_frame, text="View Logs", command=show_logs_frame, font=("Helvetica", 13), background="#118fb0", 
                        foreground="#b4fadc", relief="raised", bd=3, activebackground="#144552",activeforeground="#c5c3c6")
back_button.grid(row=4, column=2, pady=10)
back_button.config(width=15)

back_button = tk.Button(main_frame, text="Exit", command=root.quit, font=("Helvetica", 13), background="#118fb0", 
                        foreground="#b4fadc", relief="raised", bd=3, activebackground="#144552",activeforeground="red")
back_button.grid(row=6, column=2)
back_button.config(width=8)

#==================================================================================================#   
#======================================== Scan Frame Texts ========================================#
#==================================================================================================#

start_scanning_text = ttk.Label(scan_frame, text="Start Scanning", 
                      font=("Travelast",20), foreground="#b4fadc", background="#0377a8")
start_scanning_text.grid(row=0, column=2, pady=(10,5), padx=30)

select_folder_text = ttk.Label(scan_frame, text="Select Folder to Scan : ", 
                      font=("Travelast",15), foreground="white", background="#0377a8")
select_folder_text.grid(row=1, column=0,padx=(10))

scan_frame_date_text = ttk.Label(scan_frame, text=f"{today}", 
                      font=("Helvetica",12), foreground="white", background="#0377a8")
scan_frame_date_text.grid(row=0, column=5,sticky="w",padx=(10))


#====================================================================================================#   
#======================================== Scan Frame Buttons ========================================#
#====================================================================================================#

scan_frame_browse_button = tk.Button(scan_frame, text="Browse", command=browse_folder, font=("Helvetica", 10), background="#118fb0", 
                          foreground="#b4fadc", relief="raised", bd=3,activebackground="#144552",activeforeground="#1985a1")
scan_frame_browse_button.grid(row=1, column=4,sticky="e",padx=(20,10))
scan_frame_browse_button.config(width=8)

scan_frame_scan_button = tk.Button(scan_frame, text="Scan", command=lambda:check_for_possible_threats(), font=("Helvetica", 10), background="#118fb0", 
                          foreground="#b4fadc", relief="raised", bd=3,activebackground="#144552",activeforeground="#1985a1")
scan_frame_scan_button.grid(row=1, column=5,sticky="e",padx=(20,10))
scan_frame_scan_button.config(width=8)


scan_frame_back_button = tk.Button(scan_frame, text="Back", command=back_to_main, font=("Helvetica", 12), background="#118fb0", 
                        foreground="#b4fadc", relief="raised", bd=3, activebackground="#144552",activeforeground="red")
scan_frame_back_button.grid(row=6, column=0,pady=(50,5),padx=(15,10), sticky="w")
scan_frame_back_button.config(width=8)

#==================================================================================================#   
#======================================== Logs Frame Texts ========================================#
#==================================================================================================#
system_logs_text = ttk.Label(logs_frame, text="Scan Logs", 
                      font=("Travelast",20), foreground="#b4fadc", background="#0377a8")
system_logs_text.grid(row=0, column=4, pady=(10,5), padx=30)


divider_text = ttk.Label(logs_frame, text="=========================================================================================", 
                      font=("Travelast",20), foreground="#b4fadc", background="#0377a8")
divider_text.grid(row=1, column=0, pady=(10,50), padx=0,sticky="nw",columnspan=12)

log_frame_date_text = ttk.Label(logs_frame, text=f"{today}", 
                      font=("Helvetica",12), foreground="white", background="#0377a8")
log_frame_date_text.grid(row=0, column=7,sticky="w",padx=(10))


#====================================================================================================#   
#======================================== Logs Frame Buttons ========================================#
#====================================================================================================#

back_button = tk.Button(logs_frame, text="Back", command=back_to_main, font=("Helvetica", 12), background="#118fb0", 
                        foreground="#b4fadc", relief="raised", bd=3, activebackground="#144552",activeforeground="red")
back_button.grid(row=8, column=0,pady=(50,5),padx=(15,10), sticky="w")
back_button.config(width=8)

open_log_button = tk.Button(logs_frame, text="Open Log", command=open_log_file, font=("Helvetica", 12),
                            background="#118fb0", foreground="#b4fadc", relief="raised",
                            activebackground="#144552", activeforeground="red",bd=3)
open_log_button.grid(row=8, column=7, pady=(50, 5), padx=(15, 10), sticky="w")
open_log_button.config(width=8)

#====================================================================================================#   
#======================================== Scan Frame Wedgits ========================================#
#====================================================================================================#
output_field = tk.Text(scan_frame, height=15, width=60, background="#dee2e6", font=("Helvetica", 12), foreground="black", highlightthickness=0)
scrollbar = tk.Scrollbar(scan_frame, command=output_field.yview)
output_field.configure(yscrollcommand=scrollbar.set)

output_field.grid(row=2, column=0, pady=(30,5), padx=(125,10), columnspan=6, rowspan=3, sticky="w")
scrollbar.grid(row=2, column=5, pady=(30,5), padx=(0,10), rowspan=3, sticky="nsw")
output_field.config(state="normal")

root.mainloop()
