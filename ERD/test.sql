SELECT
    id, username, password, role
FROM jwt2_user ORDER BY id DESC ;

UPDATE jwt2_user set username = upper(username);