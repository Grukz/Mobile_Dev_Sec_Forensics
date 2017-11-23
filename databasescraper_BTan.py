import os
import sys
import sqlite3
import re

contacts = "contacts"
calls = "calls"
sms = "sms"
browser = "browser"

def main():

    ###
    # Returns contents of database
    ###
    print("Database information extractor")
    print("------------------------------\n\n")
    print("Default directories for apps:\n")
    print("Contacts (contacts):\t\t com.android.providers.contacts")
    print("Call logs (calls):\t\t com.android.providers.contacts")
    print("SMS/MMS history (sms):\t\t com.android.providers.telephony")
    print("Browser history (browser):\t com.android.browser\n")
    
    directory_prompt = str(input("Enter prompt: "))
    if(directory_prompt != contacts):
        if(directory_prompt != sms):
            if(directory_prompt != browser):
                if(directory_prompt != calls):
                    print("ERROR: not a valid prompt")
                    return
    if(directory_prompt == contacts):
        db_contacts()
    if(directory_prompt == calls):
        db_call_logs()
    if(directory_prompt == sms):
        db_sms_history()
    if(directory_prompt == browser):
        db_browser_history()

    ###
    # Process permissions and groups
    ###
    dump = raw_input("\nEnter the package name (ex. com.android.providers.telephony): ")
    os.system("adb shell dumpsys package " + dump + " > dump.txt")        

    gp = raw_input("\n(groups) or (permissions): ") # prompt for group or permission

    with open("dump.txt") as packperm:
        packperm = packperm.readlines()

        if(gp == "groups"):
            print("\n\nHere are all the group IDs for that package:")
            print("---------------------------")

            for l in packperm:
                if(re.findall(r'gids', l)):
                    print(l)
                    
            print("---------------------------")        
        
        elif(gp == "permissions"):
            print("\n\nHere are all the permissions for that package:")
            print("---------------------------")

            for perm in packperm:
                print perm
        
            print("---------------------------")

    ###
    # Code signing
    ###
    os.system("adb shell pm list packages -f > output.txt") # print all packages and their files

    with open("output.txt") as f:
        f = f.readlines()

    apks = open("all_apks.txt", "w+")    # create writable txt file
    packs = open("all_packs.txt", "w+")
    
    for line in f:
        # parse through entire command output
        apks.write(line.partition("=")[0])  # grab the APKs
        apks.write("\n\n")
        packs.write(line.partition("=")[-1]) # grab the packages
        packs.write("\n")
        
    cs = str(raw_input("\nEnter the APK for code signing (case sensitive!): "))
    with open("all_apks.txt") as dirp:
        dirp = dirp.readlines()

        for entry in dirp:
            if cs in entry:
                directory = entry.partition(":")[-1]    # directory of APK
                os.system("adb pull " + directory)
                break
     
    # assumed that jarsigner directory is in PATH
    os.system("jarsigner -verify -verbose -certs " + cs + " > codesigning.txt")

    with open("codesigning.txt") as csign:
        csign = csign.readlines()

    count = 0

    print("\nCN and O fields:")
    print("-----------------------\n")
    
    
    for line in csign:
        if(re.findall(r'X.509', line)):
            count += 1
            liszt = line.split(",")
            for block in liszt:
                if(('CN=' in block)) or (('O=' in block)):
                    print(block)
                    if('Android Debug' in block):
                        print("Warning: Signed with Android Debug Key") # warning check
            print("-----------------------")

    print("File count: " + str(count))
    
    apks.close()
    packs.close()

def db_contacts():
    command = "adb pull /data/data/com.android.providers.contacts/databases/contacts2.db"
    os.system(command) # db file in adb.exe directory

    sqlfile = sqlite3.connect("contacts2.db")
    cursor = sqlfile.cursor()  # open connection to sql file
    query = cursor.execute("SELECT * FROM data;")  # query all info

    print("\nContacts")
    print("--------------------")
    for log in query:
        print(log)
    print("--------------------")
    sqlfile.close()
    
def db_call_logs():
    command = "adb pull /data/data/com.android.providers.contacts/databases/contacts2.db"
    os.system(command) # db file in adb.exe directory

    sqlfile = sqlite3.connect("contacts2.db")
    cursor = sqlfile.cursor()  # open connection to sql file
    query = cursor.execute("SELECT * FROM calls;")  # query all info

    print("\nCall logs")
    print("--------------------")
    for log in query:
        print(log)
    print("--------------------")
    sqlfile.close()

def db_sms_history():
    command = "adb pull /data/data/com.android.providers.telephony/databases/mmssms.db"
    os.system(command) # db file in adb.exe directory

    sqlfile = sqlite3.connect("mmssms.db")
    cursor = sqlfile.cursor()  # open connection to sql file
    query = cursor.execute("SELECT * FROM sms;")  # query all info

    print("\nSMS history")
    print("--------------------")
    for log in query:
        print(log)
    print("--------------------")
    sqlfile.close()

def db_browser_history():
    command = "adb pull /data/data/com.android.browser/databases/browser2.db"
    os.system(command) # db file in adb.exe directory

    sqlfile = sqlite3.connect("browser2.db")
    cursor = sqlfile.cursor()  # open connection to sql file
    query = cursor.execute("SELECT * FROM history;")  # query all info

    print("\nBrowser history")
    print("--------------------")
    for log in query:
        print(log)
    print("--------------------")
    sqlfile.close()
    
main()
