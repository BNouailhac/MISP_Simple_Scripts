```
                                                   .:-=+*####################*+=-:.                             
                                              :=+#####*+=-::..        ..::-=+*#####+-:                         
                                          .-+####+=:.                          .:=+####+-.                     
                                       .=*###+-.    ...:-==++++++==:.               .-+###*=.                  
                                     -*###=:      .+########=+#######*=.    .-=:.       :+###*-                
                                  .=###+:         :::------+#########*+*+.    .###+-.      -*###=              
                                 =###=.       .-*-. .-====*##*-:+#####+ .=-    =#####*=.     :+###=            
                               -###-                 .::...      .+####+       .########*-     :+###-          
                             .*##=          .-===--:.              +####-       ###########-     :*##*.        
                            -##*.      :=+**######*+++=:           .####*       *###########*-     =###-       
                           +##-     :=###*+########+:  ..           *####:      ##############+.    :###=      
                          +##:    *####*+-###==+#####*:             *####:     :################:    .*##+     
                         +#*.    :-:-:..:+#+:    :+####=           -#####.     +#################:    .*##+    
                        +#*.    .--..-*+-.         +####=         .#####*     -###################:    .*##=   
                       -##.    .=.      ....       .#####.       :######.    -#####################.    .###-  
                      .##-         .-+##+-:.        +####+      =######:    =######################*     -###. 
                      +#+        .+#####**+-.       =####*    :*#####*.   .*########################-     *##= 
                     .##.       =*###########*:     +####*  :*######-    =##########################*     -### 
                     -#*      .**=###=---=*####*    +****=.=******+.   .+************################:     ###-
                     +#-     .###**#*      =####:.-::::::::::::::::::::::::::::::-.  :*##############*     +##+
                     *#:    .*##- =#.       *###:::   .*:        =+        :*:   -:   :###############.    =##*
                     ##.    **-::=+         +###:::  :###=      +##*.     -###-  -:    *####*::=######:    -###
                     ##.    :.-.-=          +###::: =#####+   .*#####:   =#####= -:    +####.   .#####-    -###
                     *#:     +              *###::-+#######*.:########-.+#######*=:    +###-     :####=    =##*
                     +#-    :-              ####::=#########-+########*-#########+:    *##*       *###-    +##+
                     -#+                   :####:::.*######:  =######=  .*#####*.-:   .###.       =###.    ###-
                     .##.                  +####:::  +###*.    :####-     +###*. -:   =#*.        =##+    :### 
                      +#=                 -#####:::   =#+       .*#:       =#=   -:  .#+          =##.    *##= 
                      .##.               .######::-    =         ::         =    -: :=.           *#:    =##*  
                       =#*               :######= +   +#*.      :##-       +#+   =               .#-    -##*.  
                        +#=               #######.-:.*###*.    -####=    .*###*.--              .=:    =##*.   
                         *#=              -######*.-#######-  +######+  :#######-                    -*##+     
                         .*#=              -#######::#######=*########*-######*::-:.             .-+###*:      
                          .*#=              .*######=.=####+ :########: +####=.=#####*++======+*#####*-        
                            +#+.              :+######-.=#=   .*####*.   =#=.-#####################+:          
                             -##:                :+#####=.:-:   +##+   :-:.=###################*=:             
                              .*#+.                 .:=+*#+-.:--:=+:--::-*#################+=:.                
                                -##-           -=-        .:-:.  ...:=*##########***+=-:.                      
                                  =#*-       :#####+:.                :######:                                 
                                    =##=.    :*  +######**++++++++***#########+-.                              
                                      -*#+:     :#+  .:=*#*--=++++*********+=-          .:                     
                                        .=*#+:   :-      -#.                         .-+*.                     
                                           .-+#+-:                                :=*##=                       
                                               :-+**=-:.                    .:-+*####=.                        
                                                    :-=+**++=---------==+***+==*##+:                           
```
# AMSN: API MISP

Ce code donne à disposition plusieur script permetant l'exploitation des données d'une instalation local de MISP.

## Packages python utilisés :

- json
- csv
- datetime
- pandas

## Usage
Les variables de connection à l'api MISP local ce trouve dans le fichier 'src/conf/misp_conf.py'.

### misp_create_event.py
Script pour créer un nouvel évènement dans misp

```
$ python3 ./src/create_event.py
```

### misp_attribute_csv.py
Prend tout les évènement de l'instance MISP pour en extraire les IOC et créer un fichier .csv pour chaque type d'IOC (dans le dossier attribute/)

```
$ python3 ./src/misp_attribute_csv.py
```

### misp_suricata.py
Prend tout les évènements de l'instance MISP créer des règles suricata cappable de les détectés (dans le fichier rule/misp.rules)

```
$ python3 ./src/misp_suricata.py
```

### misp_hash_rules.py
Prend tout les IOC de type hash de fichier compatible avec suricata (md5, sha1 et sha256) de l'instance MISP afin créer des fichiers les rassemblant (dans le dossier hash/) et un fichier de règles suricata détecter des hash de fichier à partir des ces fichiers (dans le fichier rule/hash.rules)

```
$ python3 ./src/misp_hash_rules.py
```

### misp_warninglist_csv.py
Prend tout les warninglist de l'instance MISP pour en extraire les IOC et créer un fichier .csv pour chaque type (dans le dossier warninglist/)

```
$ python3 ./src/misp_warninglist_csv.py
```

### misp_pull_feeds.py
A partir d'url de feeds d'IOC en ligne (lists des feeds disponible pour MISP trouvable sur notre instance local à : /feeds/index) et dépose les fichiers trouvé dans le dossier feeds/

```
$ python3 ./src/misp_pull_feeds.py
```
### misp_push_event.py
Prends tous les fichiers dans le dossier feeds et les importe dans l'instance local misp

```
$ python3 ./src/misp_push_event.py
```

## Contribution
- Baptiste Nouailhac - 02/10/2024