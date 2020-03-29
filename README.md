# hellhound
an application whitlisting solution .
This is a prototype.further development on this project is in process 
Scope:
All the Endpoints in an IT infrastructure to be covered with centralized management.
Requirement Specifications:
-	To Ensure that all the Endpoints are having Application whitelisting enabled and no illegitimate application/process is allowed to run
-	To provide a centralized dashboard for generating alerts on the illegitimate process/application tried to run 
-	To manage the application whitelistings including exceptions through same centralized dashboard.
Solution Proposed: 
The solution is designed with following approach:
i)	Open Source OSQUERY Framework+ (OSQUERY d/ OSQUERY CTL) to be installed on a Central Server
ii)	Integration with host systems having different Operating Systems will be done
iii)	Information from different systems will be collected in database
iv)	Using OSQUERY Extension and Python – to develop a functionality to disallow execution of non-whitelisted application
Technichal  Details:
-	Installing OSQUERY d and OSQUERY CTL on UBUNTU 
-	Python and Python development tools
-	MYSQL
Usefulness:
The project derives its ultimate benefit in zero day protection and in monitoring of the real time system state.
Market Potential:
Monitoring of System state/attributes is essential for any Cyber Security product and as such various organizations are looking at these types of solutions which gives granular controls on the applications and processes.
Last word and future development : 
The solution is powerful and has potential of extending it to integrate with various security technologies to provide automated responses on complex IOCs (Indicators of compromise).
