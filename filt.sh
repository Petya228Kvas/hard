#!/bin/bash
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' 
BOLD='\033[1m'

# для получения длины строки без цветовых кодов
strlen_without_colors() {
    local str="$1"
    # Удаляем все escape последовательности и считаем длину
    echo -e "$str" | sed 's/\x1b\[[0-9;]*m//g' | wc -c
}

# для форматирования строки с учетом цветов
format_colored() {
    local text="$1"
    local width="$2"
    local color_func="$3"
    
    # Получаем цветной текст
    colored_text=$(eval "$color_func \"$text\"")
    
    # Вычисляем длину без цветов
    clean_text=$(echo -e "$text" | sed 's/\x1b\[[0-9;]*m//g')
    clean_len=${#clean_text}
    
    # Добавляем пробелы до нужной ширины
    if [[ $clean_len -lt $width ]]; then
        spaces=$((width - clean_len))
        printf "%s%*s" "$colored_text" "$spaces" ""
    else
        printf "%s" "$colored_text"
    fi
}

# для окрашивания значений защит
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

# для проверки статуса защиты
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

# для форматированного вывода таблицы
print_table() {
    local -n data=$1
    
    # ширина столбцов
    local w_relro=16 w_canary=16 w_nx=13 w_pie=16 w_rpath=11 w_runpath=11
    local w_symbols=16 w_fortify=9 w_fortified=11 w_fortifiable=13
    
    # заголовки
    printf "${BOLD}%-${w_relro}s %-${w_canary}s %-${w_nx}s %-${w_pie}s %-${w_rpath}s %-${w_runpath}s %-${w_symbols}s %-${w_fortify}s %-${w_fortified}s %-${w_fortifiable}s %s${NC}\n" \
           "RELRO" "STACK CANARY" "NX" "PIE" "RPATH" "RUNPATH" "Symbols" "FORTIFY" "Fortified" "Fortifiable" "Filename"
    
    # разделитель
    printf "%s\n" "--------------------------------------------------------------------------------------------------------------------------------------------------------------------"
    
    # данные
    for row in "${data[@]}"; do
        IFS=',' read -r relro canary nx pie rpath runpath symbols fortify fortified fortifiable filename <<< "$row"
        # форматируем каждое поле с учетом цвета и выравнивания
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
        # выводим строку
        echo -e "$relro_out$canary_out$nx_out$pie_out$rpath_out$runpath_out$symbols_out$fortify_out$fortified_out$fortifiable_out $filename"
    done
}

main() {
    echo -e "${BOLD}Фильтрация файлов по защитам${NC}"
    echo "==========================================="
    # Запрашиваем путь к файлу
    echo -e "\n${BOLD}Введите путь к CSV файлу с данными:${NC}"
    read -e input_file
    
    if [ ! -f "$input_file" ]; then
        echo -e "${RED}Ошибка: Файл не существует${NC}"
        exit 1
    fi
    
    echo -e "\n${BOLD}Выберите состояние защит для фильтрации:${NC}"
    echo "0 - Выключена"
    echo "1 -Включена"
    read state
    
    if [[ "$state" != "0" && "$state" != "1" ]]; then
        echo -e "${RED}Ошибка: Неверный выбор! Надо 0 или 1!${NC}"
        exit 1
    fi
    
    # Меню выбора защит
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
    
    # Обработка выбора
    if [[ "$selection" == "all" ]]; then
        selected=(1 2 3 4 5 6 7 8 9 10)
    else
        selected=($selection)
    fi
    
    # массив с названиями полей
    field_names=("RELRO" "CANARY" "NX" "PIE" "RPATH" "RUNPATH" "SYMBOLS" "FORTIFY" "FORTIFIED" "FORTIFIABLE")
    
    # читаем файл и фильтруем
    results=()
    line_num=0
    
    echo -e "\n${BOLD}Фильтрация файла...${NC}"
    
    while IFS= read -r line || [ -n "$line" ]; do
        line_num=$((line_num + 1))
        # Пропускаем пустые строки
        if [[ -z "${line// }" ]]; then
            continue
        fi
        
        # Разбиваем строку на поля
        IFS=',' read -r relro canary nx pie rpath runpath symbols fortify fortified fortifiable filename <<< "$line"
        
        # проверяем каждую выбранную защиту
        match=true
        
        for num in "${selected[@]}"; do
            # получаем значение поля по номеру
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
            
            # проверяем защиту
            if ! check_protection "$value" "$state" "$field"; then
                match=false
                break
            fi
        done
        
        if [[ "$match" == "true" ]]; then
            results+=("$line")
        fi
        
    done < "$input_file"
    
    echo -e "\n${BOLD}====================================================================================================================================================================${NC}"
    echo -e "${BOLD}РЕЗУЛЬТАТЫ ФИЛЬТРАЦИИ${NC}"
    echo -e "${BOLD}====================================================================================================================================================================${NC}"
    
    if [ ${#results[@]} -eq 0 ]; then
        echo -e "${RED}Нет файлов, соответствующих критериям фильтрации.${NC}"
    else
        # Выводим отформатированную таблицу
        print_table results
    fi
    
    # Статистика
    echo -e "\n${BOLD}Всего обработано:${NC} $line_num"
    echo -e "${BOLD}Найдено:${NC} ${#results[@]}"
    
    # Показываем выбранные критерии
    echo -n "Состояние: "
    if [[ "$state" == "0" ]]; then
        echo -e "${RED}Выключена${NC}"
    else
        echo -e "${GREEN}Включена${NC}"
    fi
    echo -n "Защиты: "
    for num in "${selected[@]}"; do
        echo -n "${field_names[$((num-1))]} "
    done
    echo
}

# Запуск
main
