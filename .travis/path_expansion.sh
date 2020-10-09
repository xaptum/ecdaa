# For inclusion, to provide path expansion

function my_expand_path {
        if [[ "${1:0:1}" == "/" ]]; then
                echo "$1"
        else
                echo "$(pwd)/$1"
        fi
}

