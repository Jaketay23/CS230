<?php

if(isset($_POST['login-submit'])){
    require 'dbhandler.php';
    $uname_email = $_POST['uname'];
    $pawd = $_POST['pwd'];

    if(empty($uname_email)|| empty($pawd)){
        header("location: ../login.php?error=EmptyField");
        exit();
    }

    $sql = "SELECT * FROM users WHERE uname=? OR email=?;";
    $stmt = mysqli_stmt_init($conn);
    if(!mysqli_stmt_prepare($stmt, $sql)){
        header("location: ../login.php?error=SQLInjection");
        exit();
    }

    else{

        mysqli_stmt_bind_param($stmt, "ss", $uname_email, $uname_email);
        mysqli_stmt_execute($stmt);
        $result = mysqli_stmt_get_result($stmt);
        $data = mysqli_fetch_assoc($result);

        if(empty($data)){
                header("location: ../login.php?error=UserDNE");
                exit();
        }
        else{
            $passChk = password_verify($pawd, $data['password']);

            if($passChk== true){
                session_start();
                $_SESSION['uid'] = $data['uid'];
                $_SESSION['fname'] = $data['fname'];
                $_SESSION['username'] = $data['uname'];


                header("Location: ../profile.php?login_success");
                exit();
            }
            else{
                header("Location: ../login.php?errorWrongPass");
                exit();
            }
        }

    }
}
else{
    header("location: ../login.php");
    exit();
}