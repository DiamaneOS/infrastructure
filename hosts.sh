if [[ -z ${DIAMANEOS_HOSTS_FILE:-} || ! -f $DIAMANEOS_HOSTS_FILE ||
      ! -r $DIAMANEOS_HOSTS_FILE || ! -O $DIAMANEOS_HOSTS_FILE || -L $DIAMANEOS_HOSTS_FILE ]]; then
    echo 'Set DIAMANEOS_HOSTS_FILE to a current-user-owned host configuration.' >&2
    return 1
fi
if [[ -n $(find "$DIAMANEOS_HOSTS_FILE" \( -perm -020 -o -perm -002 \) -print) ]]; then
    echo "Private deployment manifests must not be writable by other users." >&2
    return 1
fi
. "$DIAMANEOS_HOSTS_FILE"
