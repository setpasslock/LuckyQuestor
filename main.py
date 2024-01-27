import requests
from rich.console import Console
from datetime import datetime
from rich.table import Table
from prompt_toolkit import prompt
from rich.panel import Panel
from rich.columns import Columns
import argparse
from rich import print
import json

arg_parser = argparse.ArgumentParser(description="Vulnerability Fallower")
arg_parser.add_argument("-l", "--limit",required=True, help="Limit for result")

args = vars(arg_parser.parse_args())
limit = args["limit"]

today_now = datetime.now()
global today_date
today_date = str(today_now.date())

def validate_date_format(user_input):
    try:
        date_object = datetime.strptime(user_input, '%Y-%m-%d')
        data_object = str(date_object).split(" ")
        return True, data_object[0]
    except:
        return False, None


def print_colored_dict(input_dict):
    console = Console()

    table = Table()
    table.add_column("Key", style="bold magenta")
    table.add_column("Value", style="bold green")

    for key, value in input_dict.items():
        table.add_row(key, json.dumps(value, indent=2, ensure_ascii=False))

    console.print(table)

def check_cve(cve):
    r_url2 = f"https://cve.circl.lu/api/cve/{cve}"
    resp = requests.get(r_url2)
    if resp.status_code == 200:
        return resp.json()

def clear_terminal():
    console = Console()
    console.clear()

def interactive_prompt(today_date_param,cve_dict,table):
    inp = prompt(f"|{today_date_param}|> ")
    console = Console()
    if inp.isnumeric():
        sonuc = check_cve(cve_dict[inp])
        res_pr = f"[b]{sonuc['id']}[/b]\nCVSS: [red]{sonuc['cvss']}[/red]\nCWE ID: [red]{sonuc['cwe']}[/red]\nPublished Date: [red]{datetime.strptime(sonuc['Published'], '%Y-%m-%dT%H:%M:%S')}[/red]\nModified Date: [red]{datetime.strptime(sonuc['Modified'], '%Y-%m-%dT%H:%M:%S')}[/red]\nLast Modified Date: [red]{datetime.strptime(sonuc['last-modified'], '%Y-%m-%dT%H:%M:%S')}[/red]\n\n[yellow]{sonuc['summary']}"
        user_renderables = [Panel(res_pr, expand=True)]
        console.print(Columns(user_renderables))
    elif isinstance(inp, str) and inp=="help":
        print("""
              <id>                                      show detail from this id
              analyze                                   group CVEs that may be related
              clear                                     clear the terminal
              date <YYYY-MM-DD>                         Edit the date format for matches. This does not fetch CVEs on the date you set, but extends
                                                        your matching to recent arrivals. You can set it to yesterday.
              details <[cyan]CVE-ID[/cyan]>             Show more details about this CVE, for example capecs, etc
              exit                                      exit the tool
              help                                      show this guide
              table                                     show the current table
              update <[cyan]limit number[/cyan]>        update the sources with limit num
              """)
    elif isinstance(inp, str) and inp=="exit":
        exit()
    elif isinstance(inp, str) and inp.startswith("details"):
        cve_p = inp.split(" ")
        try:
            cve = cve_p[1]
        except IndexError:
            pass
        r_url3 = f"https://cve.circl.lu/api/cve/{cve}"
        resp2 = requests.get(r_url3)
        if resp2.status_code == 200 and resp2.json() != None:
            data = resp2.json()
            print_colored_dict(data)
                
        elif resp2.json() == None:
            print("Not Valid CVE ID.")
    elif inp == "table":
        console.print(table)
    elif inp == "clear":
        clear_terminal()
    elif inp.startswith("update"):
        lim_p = inp.split(" ")
        try:
            limit = lim_p[1]
        except IndexError:
            pass
        main(limit=limit,today_date=today_date_param)
    elif inp.startswith("date "):
        date_p = inp.split(" ")
        try:
            date_a = date_p[1]
            isValid, date = validate_date_format(user_input=date_a)
        except:
            pass
        
        if isValid: 
            today_date = date
            main(limit=0,today_date=today_date)
        else:
            print("Not valid date format. Please YYYY-MM-DD only")
    elif inp == "analyze":
        print("The following groups are grouped with the idea that CVE numbers shared on the same day, one after the other, may be related to each other.")
        print("")
        cve_numbers = list(set(cve.split('-')[1][:4] + '-' + cve.split('-')[-1] for cve in cve_dict.values()))
        cve_numbers.sort()
        cve_number_list = []
        #for index, cve_number in enumerate(cve_numbers, start=1):
        for cve_number in cve_numbers:
            #print(f'{index}: CVE-{cve_number}')
            cve_part = cve_number.split("-")
            year = cve_part[0]
            num = cve_part[1]
            sum_str = year+num
            cve_number_list.append(sum_str)
            
        grouped_cve_numbers = []
        current_group = []

        for cve_number in cve_number_list:
            if current_group and int(cve_number) != int(current_group[-1]) + 1:
                grouped_cve_numbers.append(current_group)
                current_group = [cve_number]
            else:
                current_group.append(cve_number)

        if current_group:
            grouped_cve_numbers.append(current_group)

        for index, group in enumerate(grouped_cve_numbers, start=1):
            #print("[red]-----------------------[/red]")
            print(f'[cyan]Group[/cyan] {index}:', end=' ')
            for cve_number in group:
                cve_year = cve_number[:4]
                cve_num = cve_number[4:]
                
                cve_numm = "CVE-"+str(cve_year)+"-"+str(cve_num)+"[red]|[/red]"
                
                print(cve_numm, end=' ')
            print()
    else:
        print("""
              <id>                                      show detail from this id
              analyze                                   group CVEs that may be related
              clear                                     clear the terminal
              date <YYYY-MM-DD>                         Edit the date format for matches. This does not fetch CVEs on the date you set, but extends
                                                        your matching to recent arrivals. You can set it to yesterday.
              details <[cyan]CVE-ID[/cyan]>             show more details about this CVE, for example capecs, etc
              exit                                      exit the tool
              help                                      show this guide
              table                                     show the current table
              update <[cyan]limit number[/cyan]>        update the sources with limit num
              """)
    
def main(limit,today_date):
    table = Table(title="Today's CVE's")
    table.add_column("ID", justify="center", style="red")
    table.add_column("Published Today", justify="left", style="cyan", no_wrap=True)
    table.add_column("Modified Today", justify="left", style="cyan", no_wrap=True)

    r_url1 = f"https://cve.circl.lu/api/last/{limit}"
    resp = requests.get(r_url1).json()
    lenn = len(resp)
    row_id = 1
    cve_dict = {}
    
    for i in range(lenn):
        published_raw = datetime.strptime(resp[i]['Published'], '%Y-%m-%dT%H:%M:%S')
        published_date = str(published_raw.date())
        
        modified_date_raw = datetime.strptime(resp[i]['Modified'], '%Y-%m-%dT%H:%M:%S')
        modified_date = str(modified_date_raw.date())
        
        if published_date == today_date:
            cvss = resp[i]['cvss']
            if cvss != None:
                if cvss <= 3.0:
                    cvss = str(cvss) 
                    cvss = str("[green]"+cvss+"[/green]") 
                elif cvss <= 6.0:
                    cvss = str(cvss) 
                    cvss = str("[yellow]"+cvss+"[/yellow]")
                elif cvss <= 8.0:
                    cvss = str(cvss) 
                    cvss = str("[orange]"+cvss+"[/orange]")
                elif cvss <= 10.0:
                    cvss = str(cvss) 
                    cvss = str("[red]"+cvss+"[/red]")
            
            cvss = str(cvss)
            if cvss == "None":
                cvss = "[#1a75ff]None[/#1a75ff]"
            if len(resp[i]['id']) == 14:
                table.add_row(str(row_id),resp[i]['id']+"[#33cc33]|[/#33cc33] CVSS:"+cvss, "")
                cve_dict[str(row_id)] = resp[i]['id']
                row_id +=1
            else:
                table.add_row(str(row_id),resp[i]['id']+"[#33cc33] |[/#33cc33] CVSS:"+cvss, "")
                cve_dict[str(row_id)] = resp[i]['id']
                row_id +=1
            
        elif modified_date == today_date:
            cvss = resp[i]['cvss']
            if cvss != None:
                if cvss <= 3.0:
                    cvss = str(cvss) 
                    cvss = str("[#33cc33]"+cvss+"[/#33cc33]") 
                elif cvss <= 6.0:
                    cvss = str(cvss) 
                    cvss = str("[#ffff00]"+cvss+"[/#ffff00]")
                elif cvss <= 8.0:
                    cvss = str(cvss) 
                    cvss = str("[#ff8000]"+cvss+"[/#ff8000]")
                elif cvss <= 10.0:
                    cvss = str(cvss) 
                    cvss = str("[red]"+cvss+"[/red]")
            cvss = str(cvss)
            if cvss == "None":
                cvss = "[#1a75ff]None[/#1a75ff]"
            if len(resp[i]['id']) == 14:
                table.add_row(str(row_id),"", resp[i]['id']+"[#33cc33]|[/#33cc33] CVSS:"+cvss)
                cve_dict[str(row_id)] = resp[i]['id']
                row_id +=1
            else:
                table.add_row(str(row_id),"", resp[i]['id']+"[#33cc33] |[/#33cc33] CVSS:"+cvss)
                cve_dict[str(row_id)] = resp[i]['id']
                row_id +=1
                
    console = Console()
    console.print(table)
    #print(resp)
    while True:
        interactive_prompt(today_date_param=today_date,cve_dict=cve_dict,table=table)
        
    

main(limit=limit,today_date=today_date)