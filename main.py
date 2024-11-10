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
from typing import Dict, List, Optional
from prompt_toolkit import PromptSession
from prompt_toolkit.history import InMemoryHistory
import csv
from dataclasses import dataclass
import concurrent.futures
import threading
cve_details_cache = {}
mitre_cache_lock = threading.Lock()

@dataclass
class MitreMapping:
    attack_id: str
    tactic: str
    technique: str
    description: str
    url: str

@dataclass
class CWEMapping:
    cwe_id: str
    name: str
    description: str
    likelihood: Optional[str] = "Unknown"
    severity: Optional[str] = "Unknown"
    attack_patterns: List[str] = None

    def __post_init__(self):
        if self.attack_patterns is None:
            self.attack_patterns = []

class MitreIntegration:
    def __init__(self):
        self.attack_patterns: Dict[str, MitreMapping] = {}
        self.cwe_mappings: Dict[str, CWEMapping] = {}
        self._initialize_mappings()
    
    def _initialize_mappings(self):
        """Initialize MITRE ATT&CK and CWE mappings"""
        cache_dir = "cache"
        if not os.path.exists(cache_dir):
            os.makedirs(cache_dir)
            
        try:
            self._load_cached_mappings()
        except (FileNotFoundError, json.JSONDecodeError):
            self._fetch_and_cache_mappings()

    def _load_cached_mappings(self):
        """Load mappings from local cache files"""
        with mitre_cache_lock:
            with open('cache/mitre_attack.json', 'r') as f:
                attack_data = json.load(f)
                self.attack_patterns = {k: MitreMapping(**v) for k, v in attack_data.items()}
            
            with open('cache/mitre_cwe.json', 'r') as f:
                cwe_data = json.load(f)
                self.cwe_mappings = {k: CWEMapping(**v) for k, v in cwe_data.items()}

    def _fetch_and_cache_mappings(self):
        """Fetch latest mappings from MITRE and cache them"""
        print("[yellow]Fetching MITRE data for first time setup...[/yellow]")
        self.attack_patterns = {
            "T1190": MitreMapping(
                attack_id="T1190",
                tactic="Initial Access",
                technique="Exploit Public-Facing Application",
                description="Vulnerabilities in public-facing applications",
                url="https://attack.mitre.org/techniques/T1190/"
            ),
            "T1595": MitreMapping(
                attack_id="T1595",
                tactic="Reconnaissance",
                technique="Active Scanning",
                description="Scanning networks for vulnerabilities",
                url="https://attack.mitre.org/techniques/T1595/"
            )
        }
        self.cwe_mappings = {
            "CWE-79": CWEMapping(
                cwe_id="CWE-79",
                name="Cross-site Scripting",
                description="Improper Neutralization of Input During Web Page Generation",
                likelihood="High",
                severity="Medium",
                attack_patterns=["T1190"]
            ),
            "CWE-89": CWEMapping(
                cwe_id="CWE-89",
                name="SQL Injection",
                description="Improper Neutralization of Special Elements used in an SQL Command",
                likelihood="High",
                severity="High",
                attack_patterns=["T1190"]
            )
        }
        with mitre_cache_lock:
            with open('cache/mitre_attack.json', 'w') as f:
                json.dump({k: v.__dict__ for k, v in self.attack_patterns.items()}, f, indent=4)
            
            with open('cache/mitre_cwe.json', 'w') as f:
                json.dump({k: v.__dict__ for k, v in self.cwe_mappings.items()}, f, indent=4)
        
        print("[green]MITRE data cached successfully[/green]")

    def analyze_cve(self, cve_details: dict) -> dict:
        """Analyze CVE for MITRE ATT&CK and CWE relevance"""
        result = {
            "attack_patterns": [],
            "cwe_info": None,
            "risk_score": 0,
            "related_techniques": [],
            "mitigation_recommendations": []
        }
        
        cwe_id = cve_details.get('cwe')
        if cwe_id and cwe_id in self.cwe_mappings:
            cwe_info = self.cwe_mappings[cwe_id]
            result["cwe_info"] = {
                "name": cwe_info.name,
                "likelihood": cwe_info.likelihood,
                "severity": cwe_info.severity,
                "description": cwe_info.description
            }
            
            for pattern_id in cwe_info.attack_patterns:
                if pattern_id in self.attack_patterns:
                    attack_info = self.attack_patterns[pattern_id]
                    result["attack_patterns"].append({
                        "id": attack_info.attack_id,
                        "tactic": attack_info.tactic,
                        "technique": attack_info.technique,
                        "url": attack_info.url
                    })
        
        result["risk_score"] = self._calculate_risk_score(cve_details, result)
        result["mitigation_recommendations"] = self._generate_mitigations(result)
        
        return result

    def _calculate_risk_score(self, cve_details: dict, analysis: dict) -> float:
        """Calculate risk score based on CVSS and MITRE data"""
        base_score = float(cve_details.get('cvss', 0) or 0)
        
        if analysis["cwe_info"]:
            severity_multiplier = {
                "High": 1.2,
                "Medium": 1.0,
                "Low": 0.8,
                "Unknown": 1.0
            }.get(analysis["cwe_info"]["severity"], 1.0)
            
            likelihood_multiplier = {
                "High": 1.2,
                "Medium": 1.0,
                "Low": 0.8,
                "Unknown": 1.0
            }.get(analysis["cwe_info"]["likelihood"], 1.0)
            
            adjusted_score = base_score * severity_multiplier * likelihood_multiplier
            
            if analysis["attack_patterns"]:
                adjusted_score *= 1.1
                
            return min(10.0, adjusted_score)
        
        return base_score

    def _generate_mitigations(self, analysis: dict) -> List[str]:
        """Generate mitigation recommendations"""
        mitigations = []
        
        if analysis["cwe_info"]:
            if analysis["cwe_info"]["severity"] == "High":
                mitigations.append("Implement immediate patches and updates")
                mitigations.append("Consider additional security controls")
            elif analysis["cwe_info"]["severity"] == "Medium":
                mitigations.append("Plan for patching in next maintenance window")
            
        if analysis["attack_patterns"]:
            for pattern in analysis["attack_patterns"]:
                tactic = pattern["tactic"].lower()
                if "initial-access" in tactic:
                    mitigations.append("Strengthen access controls and authentication")
                elif "execution" in tactic:
                    mitigations.append("Implement application whitelisting")
                elif "persistence" in tactic:
                    mitigations.append("Monitor for unauthorized system modifications")
                
        return mitigations
mitre = MitreIntegration()

def display_cve_with_mitre(cve_details: dict) -> str:
    """Format CVE details with MITRE analysis for display"""
    mitre_analysis = mitre.analyze_cve(cve_details)
    
    res_pr = f"[b]{cve_details['id']}[/b]\n"
    res_pr += f"CVSS: [red]{cve_details.get('cvss', 'N/A')}[/red]\n"
    res_pr += f"CWE ID: [red]{cve_details.get('cwe', 'N/A')}[/red]\n"
    
    try:
        pub_date = datetime.strptime(cve_details['Published'], '%Y-%m-%dT%H:%M:%S')
        mod_date = datetime.strptime(cve_details['Modified'], '%Y-%m-%dT%H:%M:%S')
        last_mod_date = datetime.strptime(cve_details['last-modified'], '%Y-%m-%dT%H:%M:%S')
        
        res_pr += f"Published Date: [red]{pub_date}[/red]\n"
        res_pr += f"Modified Date: [red]{mod_date}[/red]\n"
        res_pr += f"Last Modified Date: [red]{last_mod_date}[/red]\n"
    except:
        pass
    if mitre_analysis["cwe_info"]:
        res_pr += "\n[cyan]CWE Information:[/cyan]\n"
        res_pr += f"Name: {mitre_analysis['cwe_info']['name']}\n"
        res_pr += f"Severity: {mitre_analysis['cwe_info']['severity']}\n"
        res_pr += f"Likelihood: {mitre_analysis['cwe_info']['likelihood']}\n"
    
    if mitre_analysis["attack_patterns"]:
        res_pr += "\n[cyan]MITRE ATT&CK Patterns:[/cyan]\n"
        for pattern in mitre_analysis["attack_patterns"]:
            res_pr += f"• {pattern['technique']} ({pattern['tactic']})\n"
            res_pr += f"  ID: {pattern['id']}\n"
            res_pr += f"  More info: {pattern['url']}\n"
    
    res_pr += f"\n[yellow]Risk Score: {mitre_analysis['risk_score']:.2f}/10.0[/yellow]\n"
    
    if mitre_analysis["mitigation_recommendations"]:
        res_pr += "\n[green]Mitigation Recommendations:[/green]\n"
        for rec in mitre_analysis["mitigation_recommendations"]:
            res_pr += f"• {rec}\n"
    
    res_pr += f"\n[yellow]Summary:[/yellow]\n{cve_details.get('summary', 'No summary available.')}"
    
    return res_pr
def load_watchlist():
    """Load watchlist from file with MITRE support"""
    try:
        with open('cve_watchlist.json', 'r') as f:
            data = json.load(f)
            if 'attack_techniques' not in data:
                data['attack_techniques'] = []
            if 'tactics' not in data:
                data['tactics'] = []
            if 'risk_threshold' not in data:
                data['risk_threshold'] = 7.5
            return data
    except FileNotFoundError:
        return {
            'keywords': [],
            'cwe_ids': [],
            'vendors': [],
            'attack_techniques': [],
            'tactics': [],
            'risk_threshold': 7.5
        }

def check_watchlist_match(cve_details, watchlist):
    """Check if CVE matches watchlist criteria including MITRE data"""
    for keyword in watchlist['keywords']:
        if keyword.lower() in cve_details.get('summary', '').lower():
            return True
            
    if cve_details.get('cwe') in watchlist['cwe_ids']:
        return True
            
    for vendor in watchlist['vendors']:
        if vendor.lower() in cve_details.get('summary', '').lower():
            return True
    mitre_analysis = mitre.analyze_cve(cve_details)
    for pattern in mitre_analysis["attack_patterns"]:
        if pattern["id"] in watchlist['attack_techniques']:
            return True
        if pattern["tactic"].lower() in [t.lower() for t in watchlist['tactics']]:
            return True
    if mitre_analysis["risk_score"] >= watchlist['risk_threshold']:
        return True
            
    return False
def handle_mitre_command(cmd_parts):
    """Handle MITRE-related commands"""
    if len(cmd_parts) < 2:
        print("[yellow]Usage: mitre <analyze|techniques|stats> [CVE-ID][/yellow]")
        return
        
    subcmd = cmd_parts[1]
    
    if subcmd == "analyze" and len(cmd_parts) == 3:
        cve_id = cmd_parts[2]
        details = cve_details_cache.get(cve_id) or check_cve(cve_id)
        if details:
            analysis = mitre.analyze_cve(details)
            print_colored_dict(analysis)
        else:
            print("[red]CVE not found[/red]")
            
    elif subcmd == "techniques":
        table = Table(title="Available ATT&CK Techniques")
        table.add_column("ID", style="cyan")
        table.add_column("Technique", style="green")
        table.add_column("Tactic", style="yellow")
        
        for technique in mitre.attack_patterns.values():
            table.add_row(
                technique.attack_id,
                technique.technique,
                technique.tactic
            )
        console = Console()
        console.print(table)
        
    elif subcmd == "stats":
        total_cves = len(cve_details_cache)
        cves_with_cwe = sum(1 for cve in cve_details_cache.values() if cve.get('cwe'))
        
        print(f"[cyan]MITRE Statistics:[/cyan]")
        print(f"Total CVEs analyzed: {total_cves}")
        print(f"CVEs with CWE mappings: {cves_with_cwe}")
        
    else:
        print("[yellow]Invalid MITRE command. Available commands: analyze, techniques, stats[/yellow]")

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

def save_watchlist(watchlist):
    """Save watchlist to file"""
    try:
        with open('cve_watchlist.json', 'w') as f:
            json.dump(watchlist, f, indent=4)
    except Exception as e:
        print(f"[red]Error saving watchlist: {str(e)}[/red]")

def interactive_prompt(today_date_param, cve_dict, table):
    console = Console()
    watchlist = load_watchlist()
    
    session = PromptSession(
        history=InMemoryHistory(),
    )
    fetch_and_cache_cve_details(cve_dict)
    
    while True:
        try:
            inp = session.prompt(f"|{today_date_param}|> ")
            cmd_parts = inp.split()
            
            if not cmd_parts:
                continue
                
            cmd = cmd_parts[0].lower()
            
            if cmd == "mitre":
                handle_mitre_command(cmd_parts)
                
            elif cmd == "export":
                if len(cmd_parts) != 2 or cmd_parts[1] not in ["json", "md"]:
                    print("[yellow]Usage: export <json|md>[/yellow]")
                    continue
                handle_export(cve_dict, cmd_parts[1])
                
            elif cmd == "filter":
                if len(cmd_parts) < 3:
                    print("[yellow]Usage: filter <cvss|keyword|cwe|technique|tactic> <value>[/yellow]")
                    continue
                criteria = {cmd_parts[1]: cmd_parts[2]}
                filtered = filter_cves(cve_dict, criteria)
                display_cves(filtered)
                
            elif cmd == "sort":
                if len(cmd_parts) != 2 or cmd_parts[1] not in ["cvss", "date", "risk"]:
                    print("[yellow]Usage: sort <cvss|date|risk>[/yellow]")
                    continue
                sorted_dict = sort_cves(cve_dict, cmd_parts[1])
                display_cves(sorted_dict)
                
            elif cmd == "watch":
                if len(cmd_parts) < 3:
                    print("[yellow]Usage: watch <add|remove|list> <keyword|cwe|vendor|technique|tactic|risk> <value>[/yellow]")
                    continue
                
                action = cmd_parts[1]
                
                if action == "list":
                    print("[cyan]Current Watchlist:[/cyan]")
                    print_colored_dict(watchlist)
                    continue
                
                if len(cmd_parts) < 4:
                    print("[yellow]Usage: watch <add|remove> <keyword|cwe|vendor|technique|tactic|risk> <value>[/yellow]")
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
                    elif watch_type == "technique":
                        watchlist['attack_techniques'].append(value)
                    elif watch_type == "tactic":
                        watchlist['tactics'].append(value)
                    elif watch_type == "risk":
                        try:
                            watchlist['risk_threshold'] = float(value)
                        except ValueError:
                            print("[red]Risk threshold must be a number[/red]")
                            continue
                elif action == "remove":
                    try:
                        if watch_type == "keyword":
                            watchlist['keywords'].remove(value)
                        elif watch_type == "cwe":
                            watchlist['cwe_ids'].remove(value)
                        elif watch_type == "vendor":
                            watchlist['vendors'].remove(value)
                        elif watch_type == "technique":
                            watchlist['attack_techniques'].remove(value)
                        elif watch_type == "tactic":
                            watchlist['tactics'].remove(value)
                    except ValueError:
                        print(f"[red]Value {value} not found in watchlist[/red]")
                        continue
                        
                save_watchlist(watchlist)
                print(f"[green]Watchlist {action}ed: {value}[/green]")
                
            elif cmd.isnumeric():
                if cmd in cve_dict:
                    sonuc = cve_details_cache.get(cve_dict[cmd])
                    if sonuc:
                        res_pr = display_cve_with_mitre(sonuc)
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
                    filter <cvss|keyword|cwe|technique|tactic> <value>     filter CVEs by criteria
                    help                                      show this guide
                    mitre <analyze|techniques|stats> [CVE-ID] analyze CVE with MITRE framework
                    sort <cvss|date|risk>                     sort CVEs by criteria
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
                        print("\n[cyan]MITRE Analysis:[/cyan]")
                        analysis = mitre.analyze_cve(details)
                        print_colored_dict(analysis)
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
                    cve_details_cache.clear()
                    main(limit=int(limit), today_date=today_date_param)
                except:
                    print("[red]Invalid limit value[/red]")
                    
            elif cmd.startswith("date "):
                try:
                    date_a = cmd_parts[1]
                    isValid, date = validate_date_format(date_a)
                    
                    if isValid:
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
    if cve in cve_details_cache:
        return cve_details_cache[cve]
    
    r_url2 = f"https://cve.circl.lu/api/cve/{cve}"
    try:
        resp = requests.get(r_url2)
        resp.raise_for_status()
        details = resp.json()
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
    """Export CVEs to JSON file with MITRE analysis"""
    enhanced_cve_list = []
    for cve in cve_list:
        mitre_analysis = mitre.analyze_cve(cve)
        cve_data = cve.copy()
        cve_data['mitre_analysis'] = mitre_analysis
        enhanced_cve_list.append(cve_data)
        
    with open(filename, 'w') as f:
        json.dump(enhanced_cve_list, f, indent=4)

def export_to_markdown(cve_list, filename):
    """Export CVEs to Markdown file with MITRE analysis"""
    with open(filename, 'w') as f:
        f.write("# CVE Report with MITRE Analysis\n\n")
        for cve in cve_list:
            mitre_analysis = mitre.analyze_cve(cve)
            
            f.write(f"## {cve['id']}\n")
            f.write(f"**CVSS Score:** {cve.get('cvss', 'N/A')}\n")
            f.write(f"**Risk Score:** {mitre_analysis['risk_score']:.2f}/10.0\n")
            f.write(f"**Published:** {cve['Published']}\n")
            
            if mitre_analysis['cwe_info']:
                f.write("\n### CWE Information\n")
                f.write(f"- Name: {mitre_analysis['cwe_info']['name']}\n")
                f.write(f"- Severity: {mitre_analysis['cwe_info']['severity']}\n")
                f.write(f"- Likelihood: {mitre_analysis['cwe_info']['likelihood']}\n")
            
            if mitre_analysis['attack_patterns']:
                f.write("\n### MITRE ATT&CK Patterns\n")
                for pattern in mitre_analysis['attack_patterns']:
                    f.write(f"- {pattern['technique']} ({pattern['tactic']})\n")
                    f.write(f"  - ID: {pattern['id']}\n")
                    f.write(f"  - URL: {pattern['url']}\n")
            
            if mitre_analysis['mitigation_recommendations']:
                f.write("\n### Mitigation Recommendations\n")
                for rec in mitre_analysis['mitigation_recommendations']:
                    f.write(f"- {rec}\n")
            
            f.write(f"\n### Summary\n{cve.get('summary', 'No summary available')}\n")
            
            if cve.get('references'):
                f.write("\n### References\n")
                for ref in cve['references']:
                    f.write(f"- {ref}\n")
                    
            f.write("\n---\n\n")

def filter_cves(cve_dict, criteria):
    """Filter CVEs based on various criteria including MITRE data"""
    filtered_dict = {}
    for id_num, cve_id in cve_dict.items():
        details = cve_details_cache.get(cve_id)
        if not details:
            continue
        if 'cvss' in criteria:
            min_cvss = float(criteria['cvss'])
            if not details.get('cvss') or float(details.get('cvss', 0) or 0) < min_cvss:
                continue
        if 'keyword' in criteria:
            keyword = criteria['keyword'].lower()
            summary = details.get('summary', '').lower()
            if keyword not in summary:
                continue
        if 'cwe' in criteria:
            if details.get('cwe') != criteria['cwe']:
                continue
        mitre_analysis = mitre.analyze_cve(details)
        if 'technique' in criteria:
            technique_found = False
            for pattern in mitre_analysis['attack_patterns']:
                if pattern['id'] == criteria['technique']:
                    technique_found = True
                    break
            if not technique_found:
                continue
        if 'tactic' in criteria:
            tactic_found = False
            for pattern in mitre_analysis['attack_patterns']:
                if criteria['tactic'].lower() in pattern['tactic'].lower():
                    tactic_found = True
                    break
            if not tactic_found:
                continue
                
        filtered_dict[id_num] = cve_id
    
    return filtered_dict

def sort_cves(cve_dict, sort_by='cvss', reverse=True):
    """Sort CVEs based on different criteria including risk score"""
    sorted_items = []
    for id_num, cve_id in cve_dict.items():
        details = cve_details_cache.get(cve_id)
        if details:
            if sort_by == 'risk':
                risk_score = mitre.analyze_cve(details)['risk_score']
                sorted_items.append((id_num, details, risk_score))
            else:
                sorted_items.append((id_num, details))
    
    if sort_by == 'cvss':
        sorted_items.sort(key=lambda x: float(x[1].get('cvss', 0) or 0), reverse=reverse)
    elif sort_by == 'date':
        sorted_items.sort(key=lambda x: x[1]['Published'], reverse=reverse)
    elif sort_by == 'risk':
        sorted_items.sort(key=lambda x: x[2], reverse=reverse)
    
    return {item[0]: cve_dict[item[0]] for item in sorted_items}

def display_cves(cve_dict):
    """Display CVEs in table format with MITRE info"""
    if not cve_dict:
        print("[yellow]No CVEs found matching criteria[/yellow]")
        return

    table = Table()
    table.add_column("ID", justify="center", style="red")
    table.add_column("CVE ID", style="cyan")
    table.add_column("CVSS", style="yellow")
    table.add_column("Risk Score", style="magenta")
    table.add_column("CWE", style="green")

    for id_num, cve_id in cve_dict.items():
        details = cve_details_cache.get(cve_id)
        if details:
            mitre_analysis = mitre.analyze_cve(details)
            cvss = str(details.get('cvss', 'None'))
            risk_score = f"{mitre_analysis['risk_score']:.2f}"
            cwe = details.get('cwe', 'None')
            table.add_row(id_num, cve_id, cvss, risk_score, cwe)

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
    table.add_column("Risk Score", style="magenta", no_wrap=True)

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
            if cve_id not in cve_details_cache:
                cve_details_cache[cve_id] = cve
            
            mitre_analysis = mitre.analyze_cve(cve)
            risk_score = f"{mitre_analysis['risk_score']:.2f}"
            
            if published_date == today_date or modified_date == today_date:
                has_entries = True
                if published_date == today_date:
                    table.add_row(
                        str(row_id),
                        f"{cve_id}[#33cc33]|[/#33cc33] CVSS:{cvss_colored}",
                        "",
                        risk_score
                    )
                else:
                    table.add_row(
                        str(row_id),
                        "",
                        f"{cve_id}[#33cc33]|[/#33cc33] CVSS:{cvss_colored}",
                        risk_score
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
    arg_parser = argparse.ArgumentParser(description="CVE Monitor with MITRE Integration")
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
