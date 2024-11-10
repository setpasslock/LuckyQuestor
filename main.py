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
import os

# Global cache for storing CVE details
cve_details_cache = {}

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
    # Check if CVE details are in cache
    if cve in cve_details_cache:
        return cve_details_cache[cve]
    
    # If not in cache, fetch from API
    r_url2 = f"https://cve.circl.lu/api/cve/{cve}"
    try:
        resp = requests.get(r_url2)
        resp.raise_for_status()
        details = resp.json()
        # Store in cache
        cve_details_cache[cve] = details
        return details
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

def export_to_json(cve_list, filename):
    """Export CVEs to JSON file"""
    with open(filename, 'w') as f:
        json.dump(cve_list, f, indent=4)

def export_to_markdown(cve_list, filename):
    """Export CVEs to Markdown file"""
    with open(filename, 'w') as f:
        f.write("# CVE Report\n\n")
        for cve in cve_list:
            f.write(f"## {cve['id']}\n")
            f.write(f"**CVSS Score:** {cve.get('cvss', 'N/A')}\n")
            f.write(f"**Published:** {cve['Published']}\n")
            f.write(f"**Summary:** {cve.get('summary', 'No summary available')}\n\n")
            if cve.get('references'):
                f.write("### References\n")
                for ref in cve['references']:
                    f.write(f"- {ref}\n")
            f.write("\n---\n\n")

def handle_export(cve_dict, format_type):
    """Handle export command"""
    if not cve_dict:
        print("[red]No CVEs to export[/red]")
        return
        
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"cve_report_{timestamp}.{format_type}"
    
    cve_data = []
    for cve_id in cve_dict.values():
        details = cve_details_cache.get(cve_id)
        if details:
            cve_data.append(details)
    
    if format_type == "json":
        export_to_json(cve_data, filename)
    elif format_type == "md":
        export_to_markdown(cve_data, filename)
    
    print(f"[green]Successfully exported to {filename}[/green]")

def filter_cves(cve_dict, criteria):
    """Filter CVEs based on various criteria"""
    filtered_dict = {}
    for id_num, cve_id in cve_dict.items():
        details = cve_details_cache.get(cve_id)
        if not details:
            continue
            
        # CVSS score filtering
        if 'cvss' in criteria:
            min_cvss = float(criteria['cvss'])
            if not details.get('cvss') or float(details.get('cvss', 0) or 0) < min_cvss:
                continue
                
        # Keyword filtering
        if 'keyword' in criteria:
            keyword = criteria['keyword'].lower()
            summary = details.get('summary', '').lower()
            if keyword not in summary:
                continue
                
        # CWE filtering
        if 'cwe' in criteria:
            if details.get('cwe') != criteria['cwe']:
                continue
                
        filtered_dict[id_num] = cve_id
    
    return filtered_dict

def sort_cves(cve_dict, sort_by='cvss', reverse=True):
    """Sort CVEs based on different criteria"""
    sorted_items = []
    for id_num, cve_id in cve_dict.items():
        details = cve_details_cache.get(cve_id)
        if details:
            sorted_items.append((id_num, details))
    
    if sort_by == 'cvss':
        sorted_items.sort(key=lambda x: float(x[1].get('cvss', 0) or 0), reverse=reverse)
    elif sort_by == 'date':
        sorted_items.sort(key=lambda x: x[1]['Published'], reverse=reverse)
    
    return {item[0]: cve_dict[item[0]] for item in sorted_items}

def load_watchlist():
    """Load watchlist from file"""
    try:
        with open('cve_watchlist.json', 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return {'keywords': [], 'cwe_ids': [], 'vendors': []}

def save_watchlist(watchlist):
    """Save watchlist to file"""
    with open('cve_watchlist.json', 'w') as f:
        json.dump(watchlist, f, indent=4)

def check_watchlist_match(cve_details, watchlist):
    """Check if CVE matches watchlist criteria"""
    # Check keywords
    for keyword in watchlist['keywords']:
        if keyword.lower() in cve_details.get('summary', '').lower():
            return True
            
    # Check CWE IDs
    if cve_details.get('cwe') in watchlist['cwe_ids']:
        return True
        
    # Check vendors
    for vendor in watchlist['vendors']:
        if vendor.lower() in cve_details.get('summary', '').lower():
            return True
            
    return False

def display_cves(cve_dict):
    """Display CVEs in table format"""
    if not cve_dict:
        print("[yellow]No CVEs found matching criteria[/yellow]")
        return

    table = Table()
    table.add_column("ID", justify="center", style="red")
    table.add_column("CVE ID", style="cyan")
    table.add_column("CVSS", style="yellow")

    for id_num, cve_id in cve_dict.items():
        details = cve_details_cache.get(cve_id)
        if details:
            cvss = str(details.get('cvss', 'None'))
            table.add_row(id_num, cve_id, cvss)

    console = Console()
    console.print(table)

def fetch_and_cache_cve_details(cve_dict):
    """Fetch and cache details for all CVEs"""
    print("[yellow]Fetching CVE details...[/yellow]")
    for cve_id in cve_dict.values():
        if cve_id not in cve_details_cache:
            details = check_cve(cve_id)
            if details:
                cve_details_cache[cve_id] = details
    print("[green]CVE details cached successfully[/green]")

def interactive_prompt(today_date_param, cve_dict, table):
    console = Console()
    watchlist = load_watchlist()
    
    # Fetch and cache all CVE details at startup
    fetch_and_cache_cve_details(cve_dict)
    
    while True:
        try:
            inp = prompt(f"|{today_date_param}|> ")
            cmd_parts = inp.split()
            
            if not cmd_parts:
                continue
                
            cmd = cmd_parts[0].lower()
            
            if cmd == "export":
                if len(cmd_parts) != 2 or cmd_parts[1] not in ["json", "md"]:
                    print("[yellow]Usage: export <json|md>[/yellow]")
                    continue
                handle_export(cve_dict, cmd_parts[1])
                
            elif cmd == "filter":
                if len(cmd_parts) < 3:
                    print("[yellow]Usage: filter <cvss|keyword|cwe> <value>[/yellow]")
                    continue
                criteria = {cmd_parts[1]: cmd_parts[2]}
                filtered = filter_cves(cve_dict, criteria)
                display_cves(filtered)
                
            elif cmd == "sort":
                if len(cmd_parts) != 2 or cmd_parts[1] not in ["cvss", "date"]:
                    print("[yellow]Usage: sort <cvss|date>[/yellow]")
                    continue
                sorted_dict = sort_cves(cve_dict, cmd_parts[1])
                display_cves(sorted_dict)
                
            elif cmd == "watch":
                if len(cmd_parts) < 3:
                    print("[yellow]Usage: watch <add|remove|list> <keyword|cwe|vendor> <value>[/yellow]")
                    continue
                
                action = cmd_parts[1]
                
                if action == "list":
                    print("[cyan]Current Watchlist:[/cyan]")
                    print_colored_dict(watchlist)
                    continue
                
                if len(cmd_parts) < 4:
                    print("[yellow]Usage: watch <add|remove> <keyword|cwe|vendor> <value>[/yellow]")
                    continue
                    
                watch_type = cmd_parts[2]
                value = " ".join(cmd_parts[3:])
                
                if action == "add":
                    if watch_type == "keyword":
                        watchlist['keywords'].append(value)
                    elif watch_type == "cwe":
                        watchlist['cwe_ids'].append(value)
                    elif watch_type == "vendor":
                        watchlist['vendors'].append(value)
                elif action == "remove":
                    try:
                        if watch_type == "keyword":
                            watchlist['keywords'].remove(value)
                        elif watch_type == "cwe":
                            watchlist['cwe_ids'].remove(value)
                        elif watch_type == "vendor":
                            watchlist['vendors'].remove(value)
                    except ValueError:
                        print(f"[red]Value {value} not found in watchlist[/red]")
                        continue
                        
                save_watchlist(watchlist)
                print(f"[green]Watchlist {action}ed: {value}[/green]")
                
            elif cmd.isnumeric():
                if cmd in cve_dict:
                    sonuc = cve_details_cache.get(cve_dict[cmd])
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
                    
            elif cmd == "help":
                print("""
                    <id>                                      show detail from this id
                    analyze                                   group CVEs that may be related
                    clear                                     clear the terminal
                    date <YYYY-MM-DD>                         Edit the date format for matches
                    details <CVE-ID>                          Show more details about this CVE
                    exit                                      exit the tool
                    export <json|md>                          export CVEs to file
                    filter <cvss|keyword|cwe> <value>         filter CVEs by criteria
                    help                                      show this guide
                    sort <cvss|date>                          sort CVEs by criteria
                    table                                     show the current table
                    update <limit number>                     update the sources with limit num
                    watch <add|remove|list> <type> <value>   manage watchlist
                    """)
                    
            elif cmd == "exit":
                return
                
            elif cmd.startswith("details"):
                try:
                    cve = cmd_parts[1]
                    details = cve_details_cache.get(cve) or check_cve(cve)
                    if details:
                        print_colored_dict(details)
                    else:
                        print("[red]Not Valid CVE ID.[/red]")
                except:
                    print("[red]Error processing CVE details request[/red]")
                    
            elif cmd == "table":
                console.print(table)
                
            elif cmd == "clear":
                clear_terminal()
                
            elif cmd.startswith("update"):
                try:
                    limit = cmd_parts[1]
                    # Clear cache when updating
                    cve_details_cache.clear()
                    main(limit=int(limit), today_date=today_date_param)
                except:
                    print("[red]Invalid limit value[/red]")
                    
            elif cmd.startswith("date "):
                try:
                    date_a = cmd_parts[1]
                    isValid, date = validate_date_format(date_a)
                    
                    if isValid:
                        # Clear cache when changing date
                        cve_details_cache.clear()
                        main(limit=0, today_date=date)
                    else:
                        print("[red]Not valid date format. Please use YYYY-MM-DD[/red]")
                except:
                    print("[red]Error processing date command[/red]")
                    
            elif cmd == "analyze":
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
                
        except KeyboardInterrupt:
            print("\n[yellow]Use 'exit' command to quit[/yellow]")
        except Exception as e:
            print(f"[red]Error: {str(e)}[/red]")

def main(limit, today_date=None):
    console = Console()
    
    try:
        r_url1 = f"https://cve.circl.lu/api/last/{limit}"
        resp = requests.get(r_url1)
        resp.raise_for_status()
        cve_list = resp.json()
        
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
            
            # Cache initial CVE details
            if cve_id not in cve_details_cache:
                cve_details_cache[cve_id] = cve
            
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
            break
        except KeyboardInterrupt:
            console.print("\n[yellow]Exiting...[/yellow]")
            break
        except Exception as e:
            console.print(f"[red]Error in interactive prompt: {str(e)}[/red]")
            break

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
