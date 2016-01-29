$(document).foundation();

$(document).ready(function(){
    if($('#login-modal').length > 0){
        $.get('/users/modal_login', function(data){
            $('#login-modal').append(data);
        })
    }
})
