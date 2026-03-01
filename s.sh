#!/bin/bash

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' 
BOLD='\033[1m'

get_package_info() {
    local filepath="$1"
    
    if [ ! -e "$filepath" ];then
        echo "N/A|N/A"
        return
    fi
    
    local package=$(rpm -qf "$filepath" 2>/dev/null | head -1)
    
    if [ -n "$package" ]; then
        local group=$(rpm -qi "$package" 2>/dev/null | grep -i "^Group" | cut -d':' -f2- | sed 's/^[ \t]*//' | head -1)
        
        if [ -z "$group" ]; then
            group="N/A"
        fi
        
        if [ ${#package} -gt 35 ]; then
            package="${package:0:32}    "
        fi
        
        echo "$package|$group"
    else
        echo "N/A|N/A"
    fi
}

strlen_without_colors() {
    local str="$1"
    echo -e "$str" | sed 's/\x1b\[[0-9;]*m//g' | wc -c
}

format_colored() {
    local text="$1"
    local width="$2"
    local color_func="$3"
    
    colored_text=$(eval "$color_func \"$text\"")
    clean_text=$(echo -e "$text" | sed 's/\x1b\[[0-9;]*m//g')
    clean_len=${#clean_text}
    
    if [[ $clean_len -lt $width ]]; then
        spaces=$((width - clean_len))
        printf "%s%*s" "$colored_text" "$spaces" ""
    else
        printf "%s" "$colored_text"
    fi
}

get_color() {
    local field="$1"
    local value="$2"
    
    case $field in
        "RELRO")
            if [[ "$value" == *"Full RELRO"* ]]; then
                echo "${GREEN}${value}${NC}"
            elif [[ "$value" == *"Partial RELRO"* ]]; then
                echo "${YELLOW}${value}${NC}"
            else
                echo "${RED}${value}${NC}"
            fi
            ;;
        "CANARY")
            if [[ "$value" == *"Canary found"* ]]; then
                echo "${GREEN}${value}${NC}"
            else
                echo "${RED}${value}${NC}"
            fi
            ;;
        "NX")
            if [[ "$value" == *"enabled"* ]]; then
                echo "${GREEN}${value}${NC}"
            else
                echo "${RED}${value}${NC}"
            fi
            ;;
        "PIE")
            if [[ "$value" == *"PIE enabled"* ]]; then
                echo "${GREEN}${value}${NC}"
            else
                echo "${RED}${value}${NC}"
            fi
            ;;
        "RPATH"|"RUNPATH")
            if [[ "$value" == "No RPATH" ]] || [[ "$value" == "No RUNPATH" ]]; then
                echo "${GREEN}${value}${NC}"
            elif [[ "$value" == "RUNPATH" ]] || [[ "$value" == "RPATH" ]]; then
                echo "${YELLOW}${value}${NC}"
            else
                echo "${RED}${value}${NC}"
            fi
            ;;
        "SYMBOLS")
            if [[ "$value" == "No Symbols" ]]; then
                echo "${GREEN}${value}${NC}"
            else
                echo "${RED}${value}${NC}"
            fi
            ;;
        "FORTIFY")
            if [[ "$value" == "Yes" ]]; then
                echo "${GREEN}${value}${NC}"
            elif [[ "$value" == "N/A" ]]; then
                echo "${YELLOW}${value}${NC}"
            else
                echo "${RED}${value}${NC}"
            fi
            ;;
        "FORTIFIED"|"FORTIFIABLE")
            if [[ "$value" -eq 0 ]] 2>/dev/null; then
                echo "${RED}${value}${NC}"
            else
                echo "${GREEN}${value}${NC}"
            fi
            ;;
        *)
            echo "$value"
            ;;
    esac
}

check_protection() {
    local value="$1"
    local desired_state="$2"
    local field_name="$3"
    
    case $field_name in
        "RELRO")
            if [[ "$desired_state" == "0" ]]; then
                [[ "$value" != "Full RELRO" ]] && [[ "$value" != "Partial RELRO" ]]
            else
                [[ "$value" == "Full RELRO" ]] || [[ "$value" == "Partial RELRO" ]]
            fi
            ;;
        "CANARY")
            if [[ "$desired_state" == "0" ]]; then
                [[ "$value" == "No Canary found" ]]
            else
                [[ "$value" == "Canary found" ]]
            fi
            ;;
        "NX")
            if [[ "$desired_state" == "0" ]]; then
                [[ "$value" == "NX disabled" ]]
            else
                [[ "$value" == "NX enabled" ]]
            fi
            ;;
        "PIE")
            if [[ "$desired_state" == "0" ]]; then
                [[ "$value" == "No PIE" ]]
            else
                [[ "$value" == "PIE enabled" ]]
            fi
            ;;
        "RPATH")
            if [[ "$desired_state" == "0" ]]; then
                [[ "$value" != "No RPATH" ]]
            else
                [[ "$value" == "No RPATH" ]]
            fi
            ;;
        "RUNPATH")
            if [[ "$desired_state" == "0" ]]; then
                [[ "$value" != "No RUNPATH" ]]
            else
                [[ "$value" == "No RUNPATH" ]]
            fi
            ;;
        "SYMBOLS")
            if [[ "$desired_state" == "0" ]]; then
                [[ "$value" != "No Symbols" ]]
            else
                [[ "$value" == "No Symbols" ]]
            fi
            ;;
        "FORTIFY")
            if [[ "$desired_state" == "0" ]]; then
                [[ "$value" == "No" ]]
            else
                [[ "$value" == "Yes" ]] || [[ "$value" == "N/A" ]]
            fi
            ;;
        "FORTIFIED")
            if [[ "$desired_state" == "0" ]]; then
                [[ "$value" -eq 0 ]] 2>/dev/null
            else
                [[ "$value" -gt 0 ]] 2>/dev/null
            fi
            ;;
        "FORTIFIABLE")
            if [[ "$desired_state" == "0" ]]; then
                [[ "$value" -eq 0 ]] 2>/dev/null
            else
                [[ "$value" -gt 0 ]] 2>/dev/null
            fi
            ;;
    esac
}

print_table() {
    local -n data=$1
    local -n packages=$2
    local -n groups=$3
    
    local w_relro=16 w_canary=16 w_nx=13 w_pie=16 w_rpath=11 w_runpath=11
    local w_symbols=16 w_fortify=9 w_fortified=11 w_fortifiable=13 w_packet=30 w_group=20
    
    printf "${BOLD}%-${w_relro}s %-${w_canary}s %-${w_nx}s %-${w_pie}s %-${w_rpath}s %-${w_runpath}s %-${w_symbols}s %-${w_fortify}s %-${w_fortified}s %-${w_fortifiable}s %-${w_packet}s %-${w_group}s %s${NC}\n" \
           "RELRO" "STACK CANARY" "NX" "PIE" "RPATH" "RUNPATH" "Symbols" "FORTIFY" "Fortified" "Fortifiable" "Packet" "Group" "Filename"
    
    printf "%s\n" "----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------"
    
    local current_packet=""
    for ((i=0; i<${#data[@]}; i++)); do
        row="${data[$i]}"
        packet="${packages[$i]}"
        group="${groups[$i]}"
        
        IFS=',' read -r relro canary nx pie rpath runpath symbols fortify fortified fortifiable filename <<< "$row"
        
        if [[ "$packet" != "$current_packet" ]]; then
            if [[ -n "$current_packet" ]]; then
                echo ""
            fi
            current_packet="$packet"
        fi
        
        relro_out=$(format_colored "$relro" $w_relro "get_color RELRO \"\$relro\"")
        canary_out=$(format_colored "$canary" $w_canary "get_color CANARY \"\$canary\"")
        nx_out=$(format_colored "$nx" $w_nx "get_color NX \"\$nx\"")
        pie_out=$(format_colored "$pie" $w_pie "get_color PIE \"\$pie\"")
        rpath_out=$(format_colored "$rpath" $w_rpath "get_color RPATH \"\$rpath\"")
        runpath_out=$(format_colored "$runpath" $w_runpath "get_color RUNPATH \"\$runpath\"")
        symbols_out=$(format_colored "$symbols" $w_symbols "get_color SYMBOLS \"\$symbols\"")
        fortify_out=$(format_colored "$fortify" $w_fortify "get_color FORTIFY \"\$fortify\"")
        fortified_out=$(format_colored "$fortified" $w_fortified "get_color FORTIFIED \"\$fortified\"")
        fortifiable_out=$(format_colored "$fortifiable" $w_fortifiable "get_color FORTIFIABLE \"\$fortifiable\"")
        
        packet_out=$(printf "%-${w_packet}s" "$packet")
        group_out=$(printf "%-${w_group}s" "$group")
        
        echo -e "$relro_out$canary_out$nx_out$pie_out$rpath_out$runpath_out$symbols_out$fortify_out$fortified_out$fortifiable_out$packet_out$group_out $filename"
    done
}

main() {
    echo -e "${BOLD}Фильтрация файлов по защитам${NC}"
    echo "==========================================="
    
    echo -e "\n${BOLD}Введите путь к CSV файлу с данными:${NC}"
    read -e input_file
    
    if [ ! -f "$input_file" ]; then
        echo -e "${RED}Ошибка: Файл не существует${NC}"
        exit 1
    fi
    
    echo -e "\n${BOLD}Выберите состояние защит для фильтрации:${NC}"
    echo "0 - Выключена"
    echo "1 - Включена"
    read state
    
    if [[ "$state" != "0" && "$state" != "1" ]]; then
        echo -e "${RED}Ошибка: Неверный выбор! Надо 0 или 1!${NC}"
        exit 1
    fi
    
    echo -e "\n${BOLD}Выберите какой фильтр будет использоваться:${NC}"
    echo "1 - И (AND) "
    echo "2 - ИЛИ (OR) "
    read logic
    
    if [[ "$logic" != "1" && "$logic" != "2" ]]; then
        echo -e "${RED}Ошибка: Неверный выбор! Надо 1 или 2!${NC}"
        exit 1
    fi
    
    echo -e "\n${BOLD}Выберите защиты для фильтрации:${NC}"
    echo "1 - RELRO"
    echo "2 - STACK CANARY"
    echo "3 - NX"
    echo "4 - PIE"
    echo "5 - RPATH"
    echo "6 - RUNPATH"
    echo "7 - Symbols"
    echo "8 - FORTIFY"
    echo "9 - Fortified"
    echo "10 - Fortifiable"
    echo "all"
    echo -e "${BOLD}Введите номера через пробел (например: 1 3 4):${NC}"
    read selection
    
    if [[ "$selection" == "all" ]]; then
        selected=(1 2 3 4 5 6 7 8 9 10)
    else
        selected=($selection)
    fi
    
    field_names=("RELRO" "CANARY" "NX" "PIE" "RPATH" "RUNPATH" "SYMBOLS" "FORTIFY" "FORTIFIED" "FORTIFIABLE")
    
    results=()
    line_num=0
    
    if [[ "$logic" == "1" ]]; then
        echo -e "\n${BOLD}Фильтрация файла (логика И)...${NC}"
    else
        echo -e "\n${BOLD}Фильтрация файла (логика ИЛИ)...${NC}"
    fi
    
    while IFS= read -r line || [ -n "$line" ]; do
        line_num=$((line_num + 1))
        
        if [[ -z "${line// }" ]]; then
            continue
        fi
        
        IFS=',' read -r relro canary nx pie rpath runpath symbols fortify fortified fortifiable filename <<< "$line"
        
        if [[ "$logic" == "1" ]]; then
            match=true
            for num in "${selected[@]}"; do
                case $num in
                    1) value="$relro"; field="RELRO" ;;
                    2) value="$canary"; field="CANARY" ;;
                    3) value="$nx"; field="NX" ;;
                    4) value="$pie"; field="PIE" ;;
                    5) value="$rpath"; field="RPATH" ;;
                    6) value="$runpath"; field="RUNPATH" ;;
                    7) value="$symbols"; field="SYMBOLS" ;;
                    8) value="$fortify"; field="FORTIFY" ;;
                    9) value="$fortified"; field="FORTIFIED" ;;
                    10) value="$fortifiable"; field="FORTIFIABLE" ;;
                esac
                
                if ! check_protection "$value" "$state" "$field"; then
                    match=false
                    break
                fi
            done
        else
            match=false
            for num in "${selected[@]}"; do
                case $num in
                    1) value="$relro"; field="RELRO" ;;
                    2) value="$canary"; field="CANARY" ;;
                    3) value="$nx"; field="NX" ;;
                    4) value="$pie"; field="PIE" ;;
                    5) value="$rpath"; field="RPATH" ;;
                    6) value="$runpath"; field="RUNPATH" ;;
                    7) value="$symbols"; field="SYMBOLS" ;;
                    8) value="$fortify"; field="FORTIFY" ;;
                    9) value="$fortified"; field="FORTIFIED" ;;
                    10) value="$fortifiable"; field="FORTIFIABLE" ;;
                esac
                
                if check_protection "$value" "$state" "$field"; then
                    match=true
                    break
                fi
            done
        fi
        
        if [[ "$match" == "true" ]]; then
            results+=("$line")
        fi
        
    done < "$input_file"
    
    if [ ${#results[@]} -eq 0 ]; then
        echo -e "\n${RED}Нет файлов, соответствующих критериям фильтрации.${NC}"
        exit 0
    fi
    
    echo -e "\n${BOLD}Получение информации о пакетах и группах...${NC}"
    
    declare -A packet_groups
    packet_order=()
    
    for row in "${results[@]}"; do
        IFS=',' read -r relro canary nx pie rpath runpath symbols fortify fortified fortifiable filename <<< "$row"
        info=$(get_package_info "$filename")
        packet=$(echo "$info" | cut -d'|' -f1)
        group=$(echo "$info" | cut -d'|' -f2)
        
        if [[ -z "${packet_groups[$packet]}" ]]; then
            packet_order+=("$packet")
        fi
        
        packet_groups["$packet"]="${packet_groups[$packet]}$row|$group|"
    done
    
    sorted_results=()
    sorted_packets=()
    sorted_groups=()
    
    for packet in "${packet_order[@]}"; do
        IFS='|' read -ra items <<< "${packet_groups[$packet]}"
        for ((i=0; i<${#items[@]}; i+=2)); do
            row="${items[$i]}"
            group="${items[$((i+1))]}"
            if [[ -n "$row" ]]; then
                sorted_results+=("$row")
                sorted_packets+=("$packet")
                sorted_groups+=("$group")
            fi
        done
    done
    
    echo -e "\n${BOLD}========================================================================================================================================================================================================================================${NC}"
    echo -e "${BOLD}РЕЗУЛЬТАТЫ ФИЛЬТРАЦИИ${NC}"
    echo -e "${BOLD}========================================================================================================================================================================================================================================${NC}"
    
    print_table sorted_results sorted_packets sorted_groups
    
    echo -e "\n${BOLD}Всего обработано:${NC} $line_num"
    echo -e "${BOLD}Найдено:${NC} ${#sorted_results[@]}"
    echo -e "${BOLD}Уникальных пакетов:${NC} ${#packet_order[@]}"
    
    echo -n "Состояние: "
    if [[ "$state" == "0" ]]; then
        echo -e "${RED}Выключена${NC}"
    else
        echo -e "${GREEN}Включена${NC}"
    fi
    
    echo -n "Логика: "
    if [[ "$logic" == "1" ]]; then
        echo -e "${BOLD}И (AND)${NC}"
    else
        echo -e "${BOLD}ИЛИ (OR)${NC}"
    fi
    
    echo -n "Защиты: "
    for num in "${selected[@]}"; do
        echo -n "${field_names[$((num-1))]} "
    done
    echo
}

main
