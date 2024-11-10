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
        if isinstance(value, (dict, list)):
            value_str = json.dumps(value, indent=2, ensure_ascii=False)
        else:
            value_str = str(value)
        table.add_row(str(key), value_str)

    console.print(table)

def check_cve(cve):
    r_url2 = f"https://cve.circl.lu/api/cve/{cve}"
    try:
        resp = requests.get(r_url2)
        resp.raise_for_status()
        return resp.json()
    except:
        return None

def clear_terminal():
    console = Console()
    console.clear()

def get_cvss_color(cvss):
    if cvss is None:
        return "[#1a75ff]None[/#1a75ff]"
    try:
        cvss_float = float(cvss)
        if cvss_float <= 3.0:
            return f"[green]{cvss}[/green]"
        elif cvss_float <= 6.0:
            return f"[yellow]{cvss}[/yellow]"
        elif cvss_float <= 8.0:
            return f"[orange]{cvss}[/orange]"
        else:
            return f"[red]{cvss}[/red]"
    except:
        return "[#1a75ff]None[/#1a75ff]"

def interactive_prompt(today_date_param, cve_dict, table):
    console = Console()
    inp = prompt(f"|{today_date_param}|> ")
    
    if inp.isnumeric():
        if inp in cve_dict:
            sonuc = check_cve(cve_dict[inp])
            if sonuc:
                res_pr = f"[b]{sonuc['id']}[/b]\n"
                res_pr += f"CVSS: [red]{sonuc.get('cvss', 'N/A')}[/red]\n"
                res_pr += f"CWE ID: [red]{sonuc.get('cwe', 'N/A')}[/red]\n"
                
                try:
                    pub_date = datetime.strptime(sonuc['Published'], '%Y-%m-%dT%H:%M:%S')
                    mod_date = datetime.strptime(sonuc['Modified'], '%Y-%m-%dT%H:%M:%S')
                    last_mod_date = datetime.strptime(sonuc['last-modified'], '%Y-%m-%dT%H:%M:%S')
                    
                    res_pr += f"Published Date: [red]{pub_date}[/red]\n"
                    res_pr += f"Modified Date: [red]{mod_date}[/red]\n"
                    res_pr += f"Last Modified Date: [red]{last_mod_date}[/red]\n"
                except:
                    pass
                
                res_pr += f"\n[yellow]{sonuc.get('summary', 'No summary available.')}[/yellow]"
                
                user_renderables = [Panel(res_pr, expand=True)]
                console.print(Columns(user_renderables))
            else:
                print("[red]Error fetching CVE details[/red]")
        else:
            print("[red]Invalid ID[/red]")
            
    elif inp == "help":
        print("""
              <id>                                      show detail from this id
              analyze                                   group CVEs that may be related
              clear                                     clear the terminal
              date <YYYY-MM-DD>                         Edit the date format for matches
              details <CVE-ID>                          Show more details about this CVE
              exit                                      exit the tool
              help                                      show this guide
              table                                     show the current table
              update <limit number>                     update the sources with limit num
              """)
    elif inp == "exit":
        exit()
    elif inp.startswith("details"):
        try:
            cve = inp.split(" ")[1]
            resp2 = requests.get(f"https://cve.circl.lu/api/cve/{cve}")
            data = resp2.json()
            
            if data:
                print_colored_dict(data)
            else:
                print("[red]Not Valid CVE ID.[/red]")
        except:
            print("[red]Error processing CVE details request[/red]")
            
    elif inp == "table":
        console.print(table)
    elif inp == "clear":
        clear_terminal()
    elif inp.startswith("update"):
        try:
            limit = inp.split(" ")[1]
            main(limit=int(limit), today_date=today_date_param)
        except:
            print("[red]Invalid limit value[/red]")
            
    elif inp.startswith("date "):
        try:
            date_a = inp.split(" ")[1]
            isValid, date = validate_date_format(date_a)
            
            if isValid:
                main(limit=0, today_date=date)
            else:
                print("[red]Not valid date format. Please use YYYY-MM-DD[/red]")
        except:
            print("[red]Error processing date command[/red]")
            
    elif inp == "analyze":
        print("[cyan]The following groups are grouped with the idea that CVE numbers shared on the same day, one after the other, may be related to each other.[/cyan]")
        print("")
        
        try:
            cve_numbers = list(set(cve.split('-')[1][:4] + '-' + cve.split('-')[-1] for cve in cve_dict.values()))
            cve_numbers.sort()
            cve_number_list = []
            
            for cve_number in cve_numbers:
                cve_part = cve_number.split("-")
                year = cve_part[0]
                num = cve_part[1]
                sum_str = year + num
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
                print(f'[cyan]Group[/cyan] {index}:', end=' ')
                for cve_number in group:
                    cve_year = cve_number[:4]
                    cve_num = cve_number[4:]
                    cve_numm = f"CVE-{cve_year}-{cve_num}[red]|[/red]"
                    print(cve_numm, end=' ')
                print()
        except Exception as e:
            print(f"[red]Error in analyze command: {str(e)}[/red]")
    else:
        print("[yellow]Invalid command. Type 'help' for available commands.[/yellow]")

def main(limit, today_date=None):
    console = Console()
    
    # API'den verileri al
    try:
        r_url1 = f"https://cve.circl.lu/api/last/{limit}"
        resp = requests.get(r_url1)
        resp.raise_for_status()
        cve_list = resp.json()
        
        # En son CVE'nin tarihini al
        if cve_list and not today_date:
            latest_cve = cve_list[0]
            published_raw = datetime.strptime(latest_cve['Published'], '%Y-%m-%dT%H:%M:%S')
            today_date = str(published_raw.date())
            
    except Exception as e:
        console.print(f"[red]Error fetching CVEs: {str(e)}[/red]")
        return

    table = Table(title=f"CVE's for {today_date}")
    table.add_column("ID", justify="center", style="red")
    table.add_column("Published Today", justify="left", style="cyan", no_wrap=True)
    table.add_column("Modified Today", justify="left", style="cyan", no_wrap=True)

    row_id = 1
    cve_dict = {}
    has_entries = False

    for cve in cve_list:
        try:
            published_raw = datetime.strptime(cve['Published'], '%Y-%m-%dT%H:%M:%S')
            published_date = str(published_raw.date())
            
            modified_raw = datetime.strptime(cve['Modified'], '%Y-%m-%dT%H:%M:%S')
            modified_date = str(modified_raw.date())
            
            cvss_colored = get_cvss_color(cve.get('cvss'))
            cve_id = cve['id']
            
            if published_date == today_date or modified_date == today_date:
                has_entries = True
                if published_date == today_date:
                    table.add_row(
                        str(row_id),
                        f"{cve_id}[#33cc33]|[/#33cc33] CVSS:{cvss_colored}",
                        ""
                    )
                else:
                    table.add_row(
                        str(row_id),
                        "",
                        f"{cve_id}[#33cc33]|[/#33cc33] CVSS:{cvss_colored}"
                    )
                cve_dict[str(row_id)] = cve_id
                row_id += 1
                
        except Exception as e:
            console.print(f"[red]Error processing CVE {cve.get('id', 'unknown')}: {str(e)}[/red]")
            continue

    if not has_entries:
        console.print(f"[yellow]No CVEs found for {today_date}[/yellow]")
        return

    console.print(table)

    while True:
        try:
            interactive_prompt(today_date, cve_dict, table)
        except KeyboardInterrupt:
            console.print("\n[yellow]Exiting...[/yellow]")
            break
        except Exception as e:
            console.print(f"[red]Error in interactive prompt: {str(e)}[/red]")

if __name__ == "__main__":
    arg_parser = argparse.ArgumentParser(description="CVE Monitor")
    arg_parser.add_argument("-l", "--limit", required=True, help="Limit for result", type=int)
    arg_parser.add_argument("-d", "--date", help="Specific date in YYYY-MM-DD format", required=False)
    args = arg_parser.parse_args()
    
    today_date = None
    if args.date:
        isValid, date = validate_date_format(args.date)
        if isValid:
            today_date = date
        else:
            print("[red]Invalid date format. Using latest CVE date.[/red]")
    
    main(limit=args.limit, today_date=today_date)
