When you run sudo in the u1 container, avoid asking sudo password, append this line to /etc/sudoers
```
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

your_user_name ALL = NOPASSWD : ALL
```
Note: When multiple entries match for a user, they are applied in order. Where there are multiple matches, the last match is used (which is not necessarily the most specific match).
