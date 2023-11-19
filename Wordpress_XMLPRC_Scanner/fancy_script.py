import pyfiglet
from colorama import Fore
from typing import Literal
import emoji
from termcolor import colored

#TODO: Create a startup menu 
#? 1. Ascii art and fancy
def banner():
    ASCII_art_1 = pyfiglet.figlet_format("""
          Wordpress
    DDos Scanner""")
    print(Fore.CYAN,ASCII_art_1)

def print_finding(category: str, url: str, severity: Literal["low", "medium", "high", "critical"], specific: str, subspecific: str, endmessage: str = "", confidence: str = "", exploitable: bool = False):
    severity = severity.lower()
    severity_color = 'blue'
    match severity:
        case "low":
            severity_color = 'green'
        case 'medium':
            severity_color = 'yellow'
        case 'high':
            severity_color = 'red'
        case 'critical':
            severity_color = 'red'

    # create string
    outputstring = "[" + specific + ":" + subspecific + "] " + "[" + category + "]" + " [" + severity + "] "

    # possible additions
    if endmessage:
        outputstring = outputstring + "[" + endmessage + "] "
    if confidence:
        outputstring = outputstring + "Confidence: " + confidence + "% "

    outputstring = outputstring.replace("[", colored("[", "white"))
    outputstring = outputstring.replace("]", colored("]", "white"))
    outputstring = outputstring.replace("low", colored("low" + emoji.emojize(":locked_with_key:"), severity_color, attrs=['bold']))
    outputstring = outputstring.replace("medium", colored("medium" + emoji.emojize(":warning:"), severity_color, attrs=['bold']))
    outputstring = outputstring.replace("high", colored("high" + emoji.emojize(":skull:"), severity_color, attrs=['bold']))
    outputstring = outputstring.replace("critical", colored("critical" + emoji.emojize(":collision:"), severity_color, attrs=['bold']))
    outputstring = outputstring.replace("info", colored("info", severity_color, attrs=['bold']))  # todo replace with emoji
    outputstring = outputstring.replace(category, colored(category, "blue"))
    outputstring = outputstring.replace(specific, colored(specific, "green"))
    outputstring = outputstring.replace(subspecific, colored(subspecific, "green", attrs=['bold']))

    if confidence != "":
        outputstring = outputstring.replace("Confidence: ", colored("Confidence: ", "green", attrs=['bold']))
        if int(confidence) > 70:
            outputstring = outputstring.replace(confidence + "%", colored(confidence + "%", "green"))
        elif int(confidence) > 40:
            outputstring = outputstring.replace(confidence + "%", colored(confidence + "%", "yellow", attrs=['bold']))
        else:
            outputstring = outputstring.replace(confidence + "%", colored(confidence + "%", "red", attrs=['bold']))

    if endmessage != "":
        outputstring = outputstring.replace("[" + endmessage + "]", colored("[" + endmessage + "]", "magenta"))

    if exploitable:
        outputstring = outputstring + emoji.emojize(":unlocked:")

    # add url
    outputstring = outputstring + url
    outputstring = outputstring.replace(url, colored(url, "white"))

    # todo ADD verified check at end if verified

    print(colored(outputstring, "white"))
