<?php

class signup extends Controller {

    public function index() {		
      $this->view('signup/index');
    }

    public function newUser(){
      $username = $_POST['username'];
      $password = $_POST['password'];
      
      $user = $this->model('User');  
      $user_data = $user->creat_user($username, $password);

    }

}
