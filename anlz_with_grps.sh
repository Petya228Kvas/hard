#!/bin/bash

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
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
            package="${package:0:32}..."
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

get_protection_signature() {
    local relro="$1"
    local canary="$2"
    local nx="$3"
    local pie="$4"
    local rpath="$5"
    local runpath="$6"
    local symbols="$7"
    local fortify="$8"
    local fortified="$9"
    local fortifiable="${10}"
    
    local sig=""
    
    if [[ "$relro" == *"Full RELRO"* ]]; then sig="${sig}F"; 
    elif [[ "$relro" == *"Partial RELRO"* ]]; then sig="${sig}P"; 
    else sig="${sig}N"; fi
    
    if [[ "$canary" == *"Canary found"* ]]; then sig="${sig}C"; else sig="${sig}N"; fi
    if [[ "$nx" == *"enabled"* ]]; then sig="${sig}X"; else sig="${sig}N"; fi
    if [[ "$pie" == *"PIE enabled"* ]]; then sig="${sig}E"; else sig="${sig}N"; fi
    if [[ "$rpath" == "No RPATH" ]]; then sig="${sig}R"; else sig="${sig}N"; fi
    if [[ "$runpath" == "No RUNPATH" ]]; then sig="${sig}U"; else sig="${sig}N"; fi
    if [[ "$symbols" == "No Symbols" ]]; then sig="${sig}S"; else sig="${sig}N"; fi
    if [[ "$fortify" == "Yes" ]]; then sig="${sig}Y"; 
    elif [[ "$fortify" == "N/A" ]]; then sig="${sig}A"; 
    else sig="${sig}N"; fi
    
    echo "$sig"
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
    local last_signature=""
    local first_in_packet=true
    
    for ((i=0; i<${#data[@]}; i++)); do
        row="${data[$i]}"
        packet="${packages[$i]}"
        group="${groups[$i]}"
        
        IFS=',' read -r relro canary nx pie rpath runpath symbols fortify fortified fortifiable filename <<< "$row"
        signature=$(get_protection_signature "$relro" "$canary" "$nx" "$pie" "$rpath" "$runpath" "$symbols" "$fortify" "$fortified" "$fortifiable")
        
        if [[ "$packet" != "$current_packet" ]]; then
            if [[ -n "$current_packet" ]]; then
                echo ""
            fi
            current_packet="$packet"
            last_signature=""
            first_in_packet=true
        fi
        
        # Показываем индикатор смены сигнатуры только если это не первый файл в пакете
        if [[ "$first_in_packet" == false ]] && [[ "$signature" != "$last_signature" ]]; then
            echo -e "${CYAN}~~~Смена конфигурации защит~~~${NC}"
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
        
        echo -e "$relro_out $canary_out $nx_out $pie_out $rpath_out $runpath_out $symbols_out $fortify_out $fortified_out $fortifiable_out $packet_out $group_out $filename"
        
        last_signature="$signature"
        first_in_packet=false
    done
}

# Новая функция для анализа групп защит
# Новая функция для анализа групп защит
analyze_protection_groups() {
    local input_file="$1"
    
    echo -e "\n${BOLD}Анализ групп защит (8 защит = 256 возможных групп)${NC}"
    echo "=========================================================="
    
    # Массив для хранения количества файлов в каждой группе
    declare -A group_file_counts
    # Массив для хранения уникальных пакетов в каждой группе (счетчики)
    declare -A group_packages
    # Массив для хранения множества уникальных пакетов (для избежания дубликатов)
    declare -A group_unique_packages
    
    local line_num=0
    local total_files=0
    
    while IFS= read -r line || [ -n "$line" ]; do
        line_num=$((line_num + 1))
        
        if [[ -z "${line// }" ]]; then
            continue
        fi
        
        IFS=',' read -r relro canary nx pie rpath runpath symbols fortify fortified fortifiable filename <<< "$line"
        
        local group_bits=0
        
        # CANARY (бит 0)
        if [[ "$canary" == *"Canary found"* ]]; then
            group_bits=$((group_bits | 1))
        fi
        
        # FORTIFY (бит 1)
        if [[ "$fortify" == "Yes" ]] || [[ "$fortify" == "N/A" ]]; then
            group_bits=$((group_bits | 2))
        fi
        
        # NX (бит 2)
        if [[ "$nx" == *"enabled"* ]]; then
            group_bits=$((group_bits | 4))
        fi
        
        # PIE (бит 3)
        if [[ "$pie" == *"PIE enabled"* ]]; then
            group_bits=$((group_bits | 8))
        fi
        
        # RELRO (бит 4)
        if [[ "$relro" == *"Full RELRO"* ]] || [[ "$relro" == *"Partial RELRO"* ]]; then
            group_bits=$((group_bits | 16))
        fi
        
        # RPATH (бит 5) - отсутствие RPATH считаем защитой
        if [[ "$rpath" == "No RPATH" ]]; then
            group_bits=$((group_bits | 32))
        fi
        
        # RUNPATH (бит 6) - отсутствие RUNPATH считаем защитой
        if [[ "$runpath" == "No RUNPATH" ]]; then
            group_bits=$((group_bits | 64))
        fi
        
        # SYMBOLS (бит 7) - отсутствие символов считаем защитой
        if [[ "$symbols" == "No Symbols" ]]; then
            group_bits=$((group_bits | 128))
        fi
        
        info=$(get_package_info "$filename")
        packet=$(echo "$info" | cut -d'|' -f1)
        
        group_file_counts["$group_bits"]=$((group_file_counts["$group_bits"] + 1))
        total_files=$((total_files + 1))
        
        if [[ -z "${group_unique_packages["$group_bits|$packet"]}" ]]; then
            group_unique_packages["$group_bits|$packet"]=1
            # Добавляем пакет в список для вывода
            group_packages["$group_bits"]+="$packet"$'\n'
        fi
        
    done < "$input_file"
    
    # Создаем файл для вывода результатов
    output_file="groups_anls.txt"
    
    # Записываем результаты в файл
    {
        echo "АНАЛИЗ ГРУПП ЗАЩИТ (8 защит = 256 возможных групп)"
        echo "=================================================="
        echo "Дата анализа: $(date)"
        echo "Всего обработано строк: $line_num"
        echo "Всего файлов: $total_files"
        echo ""
        
        # Выводим все группы с их двоичным представлением
        echo "Список всех найденных групп:"
        echo "-----------------------------"
        
        # Сортируем группы по номеру
        for bits in $(echo "${!group_file_counts[@]}" | tr ' ' '\n' | sort -n); do
            file_count=${group_file_counts[$bits]}
            
            # Подсчитываем количество уникальных пакетов в группе
            unique_packets_count=$(echo "${group_packages[$bits]}" | sed '/^$/d' | wc -l)
            
            # Формируем двоичное представление (8 бит)
            binary=""
            for ((i=7; i>=0; i--)); do
                if ((bits & (1 << i))); then
                    binary="${binary}1"
                else
                    binary="${binary}0"
                fi
            done
            
            # Формируем читаемое описание защит
            protections=""
            [[ $((bits & 1)) -ne 0 ]] && protections="${protections}CANARY "
            [[ $((bits & 2)) -ne 0 ]] && protections="${protections}FORTIFY "
            [[ $((bits & 4)) -ne 0 ]] && protections="${protections}NX "
            [[ $((bits & 8)) -ne 0 ]] && protections="${protections}PIE "
            [[ $((bits & 16)) -ne 0 ]] && protections="${protections}RELRO "
            [[ $((bits & 32)) -ne 0 ]] && protections="${protections}RPATH "
            [[ $((bits & 64)) -ne 0 ]] && protections="${protections}RUNPATH "
            [[ $((bits & 128)) -ne 0 ]] && protections="${protections}SYMBOLS "
            
            if [[ -z "$protections" ]]; then
                protections="все защиты отключены"
            fi
            
            echo "Группа ${binary} (${bits}):"
            echo "  Файлов: ${file_count}"
            echo "  Уникальных пакетов: ${unique_packets_count}"
            echo "  Защиты: ${protections}"
            echo "  Пакеты:"
            
            if [[ $unique_packets_count -gt 0 ]]; then
                echo "$(echo "${group_packages[$bits]}" | sed '/^$/d' | sort -u | sed 's/^/    - /')"
            else
                echo "    (нет пакетов)"
            fi
            echo ""
        done
        
        echo "-----------------------------"
        
        # Находим самую полную группу (с максимальным количеством файлов)
        max_files=0
        max_group_files=""
        
        for bits in "${!group_file_counts[@]}"; do
            count=${group_file_counts[$bits]}
            if [[ $count -gt $max_files ]]; then
                max_files=$count
                max_group_files=$bits
            fi
        done
        
        # Находим группу с максимальным количеством уникальных пакетов
        max_packages=0
        max_group_packages=""
        
        for bits in "${!group_file_counts[@]}"; do
            unique_count=$(echo "${group_packages[$bits]}" | sed '/^$/d' | wc -l)
            if [[ $unique_count -gt $max_packages ]]; then
                max_packages=$unique_count
                max_group_packages=$bits
            fi
        done
        
        if [[ -n "$max_group_files" ]]; then
            # Формируем двоичное представление для максимальной группы
            max_binary_files=""
            for ((i=7; i>=0; i--)); do
                if ((max_group_files & (1 << i))); then
                    max_binary_files="${max_binary_files}1"
                else
                    max_binary_files="${max_binary_files}0"
                fi
            done
            
            echo ""
            echo "САМАЯ ПОЛНАЯ ГРУППА (по количеству файлов):"
            echo "============================================"
            echo "Группа: ${max_binary_files} (${max_group_files})"
            echo "Количество файлов: ${max_files}"
            echo "Уникальных пакетов: $(echo "${group_packages[$max_group_files]}" | sed '/^$/d' | wc -l)"
            echo ""
            echo "Пакеты в самой полной группе:"
            echo "$(echo "${group_packages[$max_group_files]}" | sed '/^$/d' | sort -u | sed 's/^/- /')"
        fi
        
        if [[ -n "$max_group_packages" && "$max_group_packages" != "$max_group_files" ]]; then
            max_binary_packages=""
            for ((i=7; i>=0; i--)); do
                if ((max_group_packages & (1 << i))); then
                    max_binary_packages="${max_binary_packages}1"
                else
                    max_binary_packages="${max_binary_packages}0"
                fi
            done
            
            echo ""
            echo "САМАЯ ПОЛНАЯ ГРУППА (по количеству уникальных пакетов):"
            echo "======================================================="
            echo "Группа: ${max_binary_packages} (${max_group_packages})"
            echo "Количество уникальных пакетов: ${max_packages}"
            echo "Всего файлов: ${group_file_counts[$max_group_packages]}"
            echo ""
            echo "Пакеты в самой полной группе:"
            echo "$(echo "${group_packages[$max_group_packages]}" | sed '/^$/d' | sort -u | sed 's/^/- /')"
        fi
        
    } > "$output_file"
    echo -e "${GREEN}Подробные результаты анализа сохранены в файл: ${output_file}${NC}"
    
    
    # Сохраняем результаты для вывода в конце программы (ВСЕ ГРУППЫ)
    PROTECTION_GROUPS_RESULTS=$(mktemp)
    {
        echo "Всего найдено групп: ${#group_file_counts[@]}"
        echo "Всего файлов: $total_files"
        echo ""
        
        # Добавляем информацию о соответствии битов защитам
        echo "СООТВЕТСТВИЕ БИТОВ ЗАЩИТАМ:"
        echo "============================"
        echo "Бит 7 (128): SYMBOLS (отсутствие символов)"
        echo "Бит 6  (64): RUNPATH (отсутствие RUNPATH)"
        echo "Бит 5  (32): RPATH   (отсутствие RPATH)"
        echo "Бит 4  (16): RELRO"
        echo "Бит 3   (8): PIE"
        echo "Бит 2   (4): NX"
        echo "Бит 1   (2): FORTIFY"
        echo "Бит 0   (1): CANARY"
        echo ""
        echo "Краткие обозначения:"
        echo "  C - CANARY, F - FORTIFY, N - NX, P - PIE,"
        echo "  R - RELRO, Z - RPATH, U - RUNPATH, S - SYMBOLS"
        echo ""
        
        echo "ВСЕ НАЙДЕННЫЕ ГРУППЫ:"
        echo "======================"
        
        # Сортируем группы по номеру и выводим все
        for bits in $(echo "${!group_file_counts[@]}" | tr ' ' '\n' | sort -n); do
            file_count=${group_file_counts[$bits]}
            unique_count=$(echo "${group_packages[$bits]}" | sed '/^$/d' | wc -l)
            
            binary=""
            for ((i=7; i>=0; i--)); do
                if ((bits & (1 << i))); then
                    binary="${binary}1"
                else
                    binary="${binary}0"
                fi
            done
            
            # Формируем краткое описание защит
            protections=""
            [[ $((bits & 1)) -ne 0 ]] && protections="${protections}C"
            [[ $((bits & 2)) -ne 0 ]] && protections="${protections}F"
            [[ $((bits & 4)) -ne 0 ]] && protections="${protections}N"
            [[ $((bits & 8)) -ne 0 ]] && protections="${protections}P"
            [[ $((bits & 16)) -ne 0 ]] && protections="${protections}R"
            [[ $((bits & 32)) -ne 0 ]] && protections="${protections}Z"
            [[ $((bits & 64)) -ne 0 ]] && protections="${protections}U"
            [[ $((bits & 128)) -ne 0 ]] && protections="${protections}S"
            
            if [[ -z "$protections" ]]; then
                protections="none"
            fi
            
            printf "  %s : %4d файлов, %3d пакетов [%s]\n" "$binary" "$file_count" "$unique_count" "$protections"
        done
        
        echo ""
        
        # Находим самую полную группу (по количеству файлов)
        max_files=0
        max_group_files=""
        
        for bits in "${!group_file_counts[@]}"; do
            count=${group_file_counts[$bits]}
            if [[ $count -gt $max_files ]]; then
                max_files=$count
                max_group_files=$bits
            fi
        done
        
        # Находим группу с максимальным количеством уникальных пакетов
        max_packages=0
        max_group_packages=""
        
        for bits in "${!group_file_counts[@]}"; do
            unique_count=$(echo "${group_packages[$bits]}" | sed '/^$/d' | wc -l)
            if [[ $unique_count -gt $max_packages ]]; then
                max_packages=$unique_count
                max_group_packages=$bits
            fi
        done
        
        if [[ -n "$max_group_files" ]]; then
            max_binary_files=""
            for ((i=7; i>=0; i--)); do
                if ((max_group_files & (1 << i))); then
                    max_binary_files="${max_binary_files}1"
                else
                    max_binary_files="${max_binary_files}0"
                fi
            done
            
            echo "САМАЯ ПОЛНАЯ ГРУППА (по количеству файлов):"
            echo "  Группа: ${max_binary_files}"
            echo "  Количество файлов: ${max_files}"
            echo "  Уникальных пакетов: $(echo "${group_packages[$max_group_files]}" | sed '/^$/d' | wc -l)"
        fi
        
        if [[ -n "$max_group_packages" && "$max_group_packages" != "$max_group_files" ]]; then
            max_binary_packages=""
            for ((i=7; i>=0; i--)); do
                if ((max_group_packages & (1 << i))); then
                    max_binary_packages="${max_binary_packages}1"
                else
                    max_binary_packages="${max_binary_packages}0"
                fi
            done
            
            echo ""
            echo "САМАЯ ПОЛНАЯ ГРУППА (по количеству уникальных пакетов):"
            echo "  Группа: ${max_binary_packages}"
            echo "  Количество уникальных пакетов: ${max_packages}"
            echo "  Всего файлов: ${group_file_counts[$max_group_packages]}"
        fi
        
    } > "$PROTECTION_GROUPS_RESULTS"
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
    
    # Вызываем функцию анализа групп защит
    analyze_protection_groups "$input_file"
    
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
    declare -A packet_file_count
    declare -A packet_signatures
    packet_order=()
    
    for row in "${results[@]}"; do
        IFS=',' read -r relro canary nx pie rpath runpath symbols fortify fortified fortifiable filename <<< "$row"
        info=$(get_package_info "$filename")
        packet=$(echo "$info" | cut -d'|' -f1)
        group=$(echo "$info" | cut -d'|' -f2)
        signature=$(get_protection_signature "$relro" "$canary" "$nx" "$pie" "$rpath" "$runpath" "$symbols" "$fortify" "$fortified" "$fortifiable")
        
        if [[ -z "${packet_groups[$packet]}" ]]; then
            packet_order+=("$packet")
            packet_file_count[$packet]=0
        fi
        
        packet_file_count[$packet]=$((packet_file_count[$packet] + 1))
        packet_groups["$packet"]="${packet_groups[$packet]}$row|$group|"
        packet_signatures["$packet|$signature"]=$((packet_signatures["$packet|$signature"] + 1))
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
    
    echo -e "\n${BOLD}СТАТИСТИКА ПО ПАКЕТАМ:${NC}"
    echo "----------------------------------------"
    
    local total_packages=0
    local packages_with_files=0
    
    for packet in "${packet_order[@]}"; do
        if [[ "$packet" != "N/A" ]]; then
            total_packages=$((total_packages + 1))
            if [[ ${packet_file_count[$packet]} -gt 0 ]]; then
                packages_with_files=$((packages_with_files + 1))
            fi
            
            echo -e "  ${BOLD}*${NC} ${packet}: ${packet_file_count[$packet]} файл(ов)"
            
            local unique_signatures=0
            for key in "${!packet_signatures[@]}"; do
                if [[ "$key" == "$packet|"* ]]; then
                    unique_signatures=$((unique_signatures + 1))
                fi
            done
            
            if [[ $unique_signatures -gt 1 ]]; then
                echo -e "    ${YELLOW}В пакете ${unique_signatures} разных конфигурации защит${NC}"
            else
                echo -e "    ${GREEN}Все файлы используют одинаковые защиты${NC}"
            fi
        fi
    done
    
    echo "----------------------------------------"
    echo -e "${BOLD}Всего обработано:${NC} $line_num строк"
    echo -e "${BOLD}Найдено файлов:${NC} ${#sorted_results[@]}"
    echo -e "${BOLD}Уникальных пакетов:${NC} ${#packet_order[@]}"
    echo -e "${BOLD}Пакетов (исключая N/A):${NC} $total_packages"
    echo -e "${BOLD}Пакетов с файлами:${NC} $packages_with_files"
    
    echo -e "\n${BOLD}Детали фильтрации:${NC}"
    echo -n "  Состояние: "
    if [[ "$state" == "0" ]]; then
        echo -e "${RED}Выключена${NC}"
    else
        echo -e "${GREEN}Включена${NC}"
    fi
    
    echo -n "  Логика: "
    if [[ "$logic" == "1" ]]; then
        echo -e "${BOLD}И (AND)${NC}"
    else
        echo -e "${BOLD}ИЛИ (OR)${NC}"
    fi
    
    echo -n "  Защиты: "
    for num in "${selected[@]}"; do
        echo -n "${field_names[$((num-1))]} "
    done
    echo
    
    # Выводим краткие результаты анализа групп защит в конце (ВСЕ ГРУППЫ)
    echo -e "\n${BOLD}=========================================${NC}"
    echo -e "${BOLD}КРАТКИЕ РЕЗУЛЬТАТЫ АНАЛИЗА ГРУПП ЗАЩИТ${NC}"
    echo -e "${BOLD}=========================================${NC}"
    
    if [[ -f "$PROTECTION_GROUPS_RESULTS" ]]; then
        cat "$PROTECTION_GROUPS_RESULTS"
        rm -f "$PROTECTION_GROUPS_RESULTS"
    fi
    
    echo -e "\n${BOLD}Подробные результаты сохранены в файле: groups_anls.txt${NC}"
}

main
