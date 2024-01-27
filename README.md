# LuckyQuestor

LuckyQuestor is focused on monitoring CVEs published or modified CURRENT DAY. It provides an interactive interface in CLI and uses the cve.circl.lu API (API Key not required) for data sourcing. 

## Installation
uses "prompt_toolkit" to get input, "rich" for screen displays and "requests" for http requests. Dependencies can be downloaded from requirements.txt.

## Usage
You must give an argument to the -l parameter to initialize the tool. This limit will pull the last CVEs of that day, as many as you want to see, and save them in the table, categorized as published and modified, and assign an index number to each row. The ones published today are prioritized to be shown in publish, even if they are modified today.

      python3 main.py -l 40
      
<img src="img/1.png">

You have a table where CVEs are listed. You can access details about each CVE by typing its id.

<img src="img/2.png">

type help to see options

<img src="img/3.png">

Typing the id of the CVE gives you a brief summary about it. For more comprehensive information, use the details <CVE-ID> command.
When using the details command you are not restricted to the CVEs listed in the table. You can perform this operation for all CVEs.

<img src="img/4.png">

If your table is behind the output stacks, you can access the table with the table command:

<img src="img/5.png">

You can use update if you want to expand or collapse your existing table. This will recreate your table. To do this you need to set a limit again.

<img src="img/6.png">

Sometimes there are multiple vulnerabilities in a product and they can be expressed by different CVEs. The analyze command helps you to group and parse CVE ids that come one after the other.

<img src="img/7.png">

LuckyQuestor takes the current day's date as a reference and compares against it when pulling the latest CVEs from its source. To change this date, you can use the "date year/month/day" format command. This command will not retrieve data from that date. It shows you the data that matches that date.

<img src="img/8.png">










