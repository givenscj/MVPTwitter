function RemoveFollowersByTweetDate($followers, $days)
{
    foreach($userId in $followers.keys)
    {
        $userName = $followers[$userId];

        RemoveFollowerByTweetDate $userId $userName $days;
    }    
}

function RemoveFollowerByTweetDate($userId, $userName, $days)
{
    $results = GetUserId $username;

    if (!$results)
    {
        return;
    }

    $ts = [DateTime]::NOW - $results[2];

    if ($ts.TOtalDays -gt $days)
    {
        write-host "`tRemoving user [$userName] - has not tweeted in $($ts.totaldays)" -ForegroundColor Red;        
        add-content "c:\temp\BadUsers.txt" $username;
        UnfollowUserApi $userId $userName;
        return;
    }

    if ($ts.TotalDays -lt $days / 3)
    {
        write-host "`tUser [$userName] - has not tweeted in $($ts.totaldays)" -ForegroundColor Green;
        return;
    }

    if ($ts.TotalDays -lt $days / 3 * 2)
    {
        write-host "`tUser [$userName] - has not tweeted in $($ts.totaldays)" -ForegroundColor Yellow;
        return;
    }
}

function GetFollowers($userName)
{
    $ht = new-object System.Collections.Hashtable;

    #get current user's followers
    $url = "https://twitter.com/$username/following";

    try
    {
        $results = DoGet $url $global:authCookies;                   
        $position = ParseValue $results "data-min-position=`"" "`"";
        $hasMoreItems = $true;

        while($position -and $hasMoreItems)
        {
            $url = "https://twitter.com/$username/following/users?include_available_features=1&include_entities=1&max_position=$position&reset_error_state=false";
            $global:Referer = "https://twitter.com/$global:username/following";
            $global:accept = "application/json, text/javascript, */*; q=0.01";
            $global:headers.add("X-Requested-With","XMLHttpRequest");       
            $results = DoGet $url $global:authCookies;
            
            $json = ConvertFrom-Json $results;

            $temp = $json.items_html;
            
            while($temp.contains("data-item-id=") -and $temp.contains("data-screen-name="))
            {
                $tuserId = ParseValue $temp "data-item-id=`"" "`"";
                $tuserName = ParseValue $temp "data-screen-name=`"" "`"";
                
                if (!$ht.ContainsKey($tuserId))
                {
                    $ht.Add($tuserId, $tusername);
                }

                $temp = $temp.substring($temp.indexof("data-screen-name=")+20);
            }

            $hasMoreItems = [bool]$json.has_more_items;
            $position = $json.min_position;
        }
    }
    catch
    {
    }

    return $ht;
}

function CheckMvpType($type, $createLists, $listmode)
{
    write-host "Getting $type MVPs";

    $lines = get-content "$type-ids.txt"

    if ($createLists)
    {
        CreateList $type $type $listMode;
    }

    foreach($id in $lines)
    {   
        CheckUsername $id $createLists $type;
    }
}

function CheckUsername($id, $createLists, $type)
{
    $result = GetUserId $id;

    if (!$result)
    {
        continue;
    }

    $userid = $result[0];
    $isFollowing = $result[1];

	if ($userId.length -gt 0)
	{
        if ($createLists)
        {
            AddUserToList $type $userId $id;
        }
        else
        {
            if ($isFollowing)
            {
                Write-Host "`tYou already follow $id" -ForegroundColor Yellow;
            }
            else
            {                    
	            FollowUserApi $userId $id;
            }
        }
	}
}

function ParseValue($line, $startToken, $endToken)
{
    if ($startToken -eq $null)
    {
    return "";
    }

    if ($startToken -eq "")
    {
    return $line.substring(0, $line.indexof($endtoken));
    }
    else
    {
    $rtn = $line.substring($line.indexof($starttoken));
    return $rtn.substring($startToken.length, $rtn.indexof($endToken, $startToken.length) - $startToken.length).replace("`n","").replace("`t","");
    }
}

function DoGet($url, $strCookies)
{
    $cookies = new-object system.net.CookieContainer
    $uri = new-object uri($url);
    $httpReq = [system.net.HttpWebRequest]::Create($uri)
    $httpReq.Accept = "text/html, application/xhtml+xml, */*"
    $httpReq.method = "GET"

    if ($global:referer)
    {
        $httpReq.Referer = $global:referer;
        $global:referer = $null;
    }

    if ($strCookies.length -gt 0)
    {
        $httpReq.Headers.add("Cookie", $strCookies)
    }

    foreach($key in $global:headers.keys)
    {
        $httpReq.headers.add($key, $global:headers[$key]);
    }   

    $global:headers = New-Object System.Collections.Hashtable;

    if ($global:accept)
    {
        $httpReq.Accept = "application/json, text/javascript, */*; q=0.01"
        $global:accept = $null;
    }

    try
    {
        $res = $httpReq.GetResponse()
        $rs = $res.GetResponseStream();
        [System.IO.StreamReader]$sr = New-Object System.IO.StreamReader -argumentList $rs;
        [string]$results = $sr.ReadToEnd();

        #get the cookies
        $global:strCookies = $res.Headers["set-cookie"].toString();                    
        $res.Close(); 
    }
    catch
    {
        $httpMessage = $null;

        #get the error response body...
        if ($_.Exception.InnerException.Response)
        {
            $rs = $_.Exception.InnerException.Response.GetResponseStream();
            [System.IO.StreamReader]$sr = New-Object System.IO.StreamReader -argumentList $rs;
            [string]$httpMessage = $sr.ReadToEnd();
            $global:strCookies = $_.Exception.InnerException.Response.Headers["set-cookie"].toString();
        }

        if ($_.Exception.Message)
        {
            write-host $_.Exception.Message -ForegroundColor red;
        }

        if ($httpMessage)
        {
            write-host $httpMessage -ForegroundColor Red;

            if ($httpMessage.contains("Your account may not be allowed to perform this action"))
            {
                write-host "You have been throttled by Twitter, wait an hour and re-try your operation!" -ForegroundColor Cyan;
                exit;
            }
        }
    }
    
    return $results;
}

$global:headers = New-Object System.Collections.Hashtable;
$global:location = "";
$global:allowAutoRedirect = $false;

function DoPost($url, $post, $strCookies )
{
    $encoding = new-object system.text.asciiencoding
    $buf = $encoding.GetBytes($post)
    $uri = new-object uri($url);
    $httpReq = [system.net.HttpWebRequest]::Create($uri)
    $httpReq.AllowAutoRedirect = $global:allowAutoRedirect;
    $httpReq.method = "POST"

    if ($global:referer)
    {
        $httpReq.Referer = $global:referer;
        $global:referer = $null;
    }

    $httpReq.contentlength = $buf.length
    $httpReq.Headers.add("Cookie", $strCookies)
    $httpReq.ContentType = "application/x-www-form-urlencoded; charset=UTF-8"
    $httpReq.Accept = "text/html, application/xhtml+xml, */*"

    foreach($key in $global:headers.keys)
    {
        $httpReq.headers.add($key, $global:headers[$key]);
    }   

    $global:headers = New-Object System.Collections.Hashtable;

    if ($global:accept)
    {
        $httpReq.Accept = "application/json, text/javascript, */*; q=0.01"
        $global:accept = $null;
    }

    #$httpReq.ContentType = "application/x-www-form-urlencoded"
    $httpReq.headers.Add("Accept-Language", "en-US,en;q=0.91,de-DE;q=0.82,de;q=0.73,nl-NL;q=0.64,nl;q=0.55,es-MX;q=0.45,es;q=0.36,ru;q=0.27,fr-FR;q=0.18,fr;q=0.091")
    $httpReq.UserAgent = "Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; rv:11.0) like Gecko"
    $stream = $httpReq.GetRequestStream()

    [void]$stream.write($buf, 0, $buf.length)
    $stream.close()

    try
    {
        $res = $httpReq.GetResponse()

        try
        {
            $global:location = $res.Headers["Location"].ToString();
        }
        catch
        {
        }

        $rs = $res.GetResponseStream();
        [System.IO.StreamReader]$sr = New-Object System.IO.StreamReader -argumentList $rs;
        [string]$results = $sr.ReadToEnd();
        $global:strCookies = $res.Headers["set-cookie"].toString();                    
    }
    catch
    {
        $httpMessage = $null;

        #get the error response body...
        if ($_.Exception.InnerException.Response)
        {
            $rs = $_.Exception.InnerException.Response.GetResponseStream();
            [System.IO.StreamReader]$sr = New-Object System.IO.StreamReader -argumentList $rs;
            [string]$httpMessage = $sr.ReadToEnd();
            $global:strCookies = $_.Exception.InnerException.Response.Headers["set-cookie"].toString();
        }

        if ($_.Exception.Message)
        {
            write-host $_.Exception.Message -ForegroundColor red;
        }

        if ($httpMessage)
        {
            write-host $httpMessage -ForegroundColor Red;

            if ($httpMessage.contains("Your account may not be allowed to perform this action"))
            {
                write-host "You have been throttled by Twitter, wait an hour and re-try your operation!" -ForegroundColor Cyan;
                exit;
            }
        }
    }

    #return $results
}

function GetUserId($username)
{
    write-host "Looking up user $username" -ForegroundColor White;    

    $url = "https://twitter.com/$username";

    $headers.Add("Origin", "https://twitter.com");
    $results = DoGet $url $global:authCookies;

    try
    {   
        $userId = ParseValue $results "role=`"navigation`" data-user-id=`"" "`""

        #return the userId...
        $userId;

        #determine if following or not...
        $temp = ParseValue $results "user-actions btn-group" "data-user-id=`"$userId"        

        #return the following flag
        if ($temp.contains("not-following"))
        {
            $false;
        }
        else
        {
            $true;
        }    

        try
        {
            #get the last post date...
            $posts = ParseValue $results "<ol class=`"stream-items" "</ol>";
            $posts = "<ol class=`"" + $posts + "</ol>";
        
            while($posts.contains("<li"))
            {
                $post = ParseValue $posts "<li" "</li>";

                if ($post.contains("Pinned"))
                {
                    $posts = $posts.substring($posts.indexof("</li>"));
                    continue;
                }

                $postDate = ParseValue $post "tweet-timestamp" ">";
                $postDate = ParseValue $postDate "title=`"" "`""
                $vals = $postDate.SPlit("-");
                $postDate = $vals[1] + " " + $vals[0];
                $postDate = [System.DateTime]::Parse($postDate);

                #return the postdate
                $postDate;
                break;            

                $posts = $posts.substring($posts.indexof("</li>"));
            }        
        }
        catch
        {
            [DateTime]::Now;
        }
    }
    catch
    {
        if ($_.Exception.message.contains("(404)"))
        {
            write-host "User [$username] not found" -ForegroundColor Red;
        }

        return $null;
    }
}

$listPrefix = "mvp";

function ParseListName($listName)
{
    if (!$listName.startswith($listPrefix))
    {
        $listName = "$listPrefix-$listName";
    }

    $listName = $listName.replace(" ","-");

    switch($listName)
    {
        "mvp-cloud-and-datacenter-management"
        {
            $listName = "mvp-cloud-dc-management";
        }
        "mvp-visual-studio-and-development-technologies"
        {
            $listName = "mvp-visualstudio-dev-tech";
        }
        "mvp-office-servers-and-services"
        {
            $listName = "mvp-office-servers-svcs";
        }
    }

    return $listName.tolower();
}

function GetListId($listName)
{
    $listName= ParseListName $listName;

    Write-Warning "Getting list id [$listName]";    
    
    $global:accept = "application/json, text/javascript, */*; q=0.01";
    $global:Referer = "https://twitter.com/$global:username/lists";
    $global:headers.add("X-Requested-With","XMLHttpRequest");    
    $global:headers.add("X-Push-State-Request","true");    
    $global:headers.add("X-Asset-Version","dc8358");    
    
    try
    {
        $response = DoGet "https://twitter.com/$global:username/lists/$listName" $global:authCookies    
    }
    catch
    {
        return $null;
    }

    if (!$response)
    {
        return $Null;
    }

    $data = ConvertFrom-Json $response;

    $data.init_data.list_id;
    $data.init_data.userId;
}

function AddUserToList($listName, $userId, $userName)
{
    $listName= ParseListName $listName;

    Write-Warning "Adding to list $listName";    

    $vals = GetListId $listName;

    if ($vals)
    {
        $listId = $vals[0];
        $currentuserId = $vals[1];
    
        $global:accept = "application/json, text/javascript, */*; q=0.01";
        $global:Referer = "https://twitter.com/$username";

        $global:headers.add("X-Requested-With","XMLHttpRequest");    

        $post = "authenticity_token=" + $global:pageAuthToken;

        try
        {
            $response = DoPost "https://twitter.com/i/$userId/lists/$listId/members" $post $global:authCookies;
        }
        catch
        {            
            write-host "Adding [$userName] to [$listName] failed";
        }
    }
}

function CreateList($listName, $desc, $mode)
{
    $listName= ParseListName $listName;

    #check to see if the list exists...
    $vals = GetListId $listName;

    if ($vals.length -ne 2)
    {
        Write-Warning "Creating list $listName";

        #SetCookie;
    
        $global:accept = "application/json, text/javascript, */*; q=0.01";
        $global:Referer = "https://twitter.com/$global:username/lists";

        $global:headers.add("X-Requested-With","XMLHttpRequest");       

        $post = "authenticity_token=" + $global:pageAuthToken + "&description=$desc&mode=$mode&name=$listname"
        $response = DoPost "https://twitter.com/i/lists/create" $post $global:authCookies
    }
}

function UnfollowUser($userId, $name)
{
    Write-Host "Following user $userId" -ForegroundColor Green;    
    
    $global:accept = "application/json, text/javascript, */*; q=0.01";
    $global:Referer = "https://twitter.com/$name";

    $global:headers.add("X-Requested-With","XMLHttpRequest");
    $global:headers.add("DNT","1");    
    $global:headers.add("Origin","https://twitter.com");    

    $post = "authenticity_token=" + $global:pageAuthToken + "&challenges_passed=false&handles_challenges=1&user_id=$userId"
    $response = DoPost "https://twitter.com/i/user/unfollow" $post $global:authCookies
}

function UnfollowUserApi($userId, $name)
{
    Write-Host "Following user $userId" -ForegroundColor Green;  

    SetCookie;  
    
    $global:accept = "application/json, text/javascript, */*; q=0.01";
    $global:Referer = "https://twitter.com/$name";

    $global:headers.add("Origin","https://twitter.com");
    $global:headers.add("x-csrf-token",$global:csrfToken);    
    $global:headers.add("authorization","Bearer $global:apiBearerToken");    
    $global:headers.add("x-twitter-auth-type","OAuth2Session");    
    $global:headers.add("X-Twitter-Active-User","yes");    
    
    $post = "challenges_passed=false&handles_challenges=1&include_blocked_by=true&include_blocking=true&include_can_dm=true&include_followed_by=true&include_mute_edge=true&skip_status=true&user_id=$userId";
    $response = DoPost "https://api.twitter.com/1.1/friendships/destroy.json" $post $global:authCookies
}

function FollowUser($userId, $name)
{
    Write-Host "Following user $userId" -ForegroundColor Green;    
    
    $global:accept = "application/json, text/javascript, */*; q=0.01";
    $global:Referer = "https://twitter.com/$name";

    $global:headers.add("X-Requested-With","XMLHttpRequest");
    $global:headers.add("DNT","1");    
    $global:headers.add("Origin","https://twitter.com");    

    $post = "authenticity_token=" + $global:pageAuthToken + "&challenges_passed=false&handles_challenges=1&user_id=$userId"
    $response = DoPost "https://twitter.com/i/user/follow" $post $global:authCookies
}

function SendDirectMessage($name, $message)
{
    $result = GetUserId $name;
    $targetuserid = $result[0];
    $isFollowing = $result[1];

    Write-Host "Sending Message to $targetUserId" -ForegroundColor Green;    
    
    $global:accept = "application/json, text/javascript, */*; q=0.01";
    $global:Referer = "https://twitter.com/$name";

    $global:headers.add("X-Twitter-Active-User","yes");
    $global:headers.add("X-Requested-With","XMLHttpRequest");
    $global:headers.add("DNT","1");
    $global:headers.add("Origin","https://twitter.com");    

    $convoId = $userId.tostring() + "-" + $targetuserId.tostring();

    $post = "authenticity_token=" + $global:pageAuthToken + "&conversation_id=$convoId&resend_id=1&scribeContext%5Bcomponent%5D=tweet_box_dm&tagged_users=&text=$message&tweetboxId=swift_tweetbox_1512536683287";
    $response = DoPost "https://twitter.com/i/direct_messages/new" $post $global:authCookies
}

function FollowUserApi($userId, $name)
{
    Write-Host "Following user $userId" -ForegroundColor Green;  

    SetCookie;  
    
    $global:accept = "application/json, text/javascript, */*; q=0.01";
    $global:Referer = "https://twitter.com/$name";

    $global:headers.add("Origin","https://twitter.com");
    $global:headers.add("x-csrf-token",$global:csrfToken);    
    $global:headers.add("authorization","Bearer $global:apiBearerToken");    
    $global:headers.add("x-twitter-auth-type","OAuth2Session");    
    $global:headers.add("X-Twitter-Active-User","yes");    
    
    $post = "challenges_passed=false&handles_challenges=1&include_blocked_by=true&include_blocking=true&include_can_dm=true&include_followed_by=true&include_mute_edge=true&skip_status=true&user_id=$userId";
    $response = DoPost "https://api.twitter.com/1.1/friendships/create.json" $post $global:authCookies
}

function SetCookie()
{
    $global:authCookies = "lang=en; "    
    $global:authCookies += "remember_checked_on=1; "
    $global:authCookies += "_twitter_sess=" + $global:session + "; "
    $global:authCookies += "kdt=" + $global:kdt + "; "
    $global:authCookies += "guest_id=" + $global:guestId + "; "
    $global:authCookies += "twid=" + $global:twid + "; "
    $global:authCookies += "ct0=" + $global:csrfToken + "; "
    $global:authCookies += "auth_token=" + $global:loginAuthToken + "; "
    $global:authCookies += "personalization_id=" + $global:personalId;
}

function Login($username, $password)
{    
    write-host "NOTE: Twitter will only let you login 10 times in one hour before you are throttled!" -BackgroundColor Yellow;

    $global:csrfToken = $null;
    $global:apiBearerToken = $null;

    $cookie = "_twitter_sess=" + $global:session;    
    
    <#
    $pair = $username + ":" + $password;
    $bytes = [System.Text.Encoding]::ASCII.GetBytes($pair)
    $base64 = [System.Convert]::ToBase64String($bytes)
    
    $global:headers.add("Authorization","Basic $base64");
    $post = "grant_type=client_credentials&authenticity_token=" + $global:pageAuthToken;
    $global:contentTypeOverride = "application/x-www-form-urlencoded;charset=UTF-8";

    $getApiToken = DoPost "https://api.twitter.com/oauth2/token" $post;
    #>

    #authenticity_token=" + $global:authToken + "
    $post = "session%5Busername_or_email%5D=" + $username + "&session%5Bpassword%5D=" + $password + "&authenticity_token=" + $global:pageAuthToken + "&return_to_ssl=true&scribe_log=&redirect_after_login=&remember_me=1"
    $response = DoPost "https://twitter.com/sessions" $post $cookie;

    $global:session = ParseValue $global:strCookies "_twitter_sess=" ";"

    SetCookie;

    if ($global:location.contains("login_verification"))
    {
        $response = DoGet $global:location $global:authCookies;

        #ask for the verification code...
        $code = Read-Host 'What is the sms verification code?';

        $auth_token = ParseValue $response "authenticity_token`" value=`"" "`"";
        $global:csrfToken = $auth_token;
        $challengeId = ParseValue $response "challenge_id`" value=`"" "`"";
        $global:userId = ParseValue $response "user_id`" value=`"" "`"";

        $post = "authenticity_token=$auth_token&challenge_id=$challengeId&user_id=$global:userId&challenge_type=Sms&platform=web&redirect_after_login=&remember_me=true&challenge_response=$code";

        $global:allowAutoRedirect = $false;
        $response = DoPost "https://twitter.com/account/login_verification" $post $global:authCookies;
    }

    try
    {
        $global:loginAuthToken = ParseValue $global:strCookies "auth_token=" ";"
        $global:twid = ParseValue $global:strCookies "twid=" ";"
        $global:kdt = ParseValue $global:strCookies "kdt=" ";"
        $global:session = ParseValue $global:strCookies "_twitter_sess=" ";"
        $global:personalId = ParseValue $global:strCookies "personalization_id=" ";"
    }
    catch 
    {
        write-host $_.Exception.Message;
    }

    SetCookie;

    #track down our bearer token...
    $headers.Add("Origin", "https://twitter.com");
    $global:Referer  = "https://twitter.com/account/login_verification?platform=web&user_id=$global:userId&challenge_type=Sms&challenge_id=$challengeId&remember_me=false&redirect_after_login_verification=%2F";
    $html = DoGet "https://twitter.com" $global:authCookies;
    
    #get the JS file with the bearer token in it...
    $initEnId = ParseValue $html "rel=`"preload`" href=`"https://abs.twimg.com/k/en/init.en." ".js";
    $initEnId = "https://abs.twimg.com/k/en/init.en.$initEnId.js";

    $js = DoGet $initEnId $global:authCookies;
    $global:apiBearerToken = ParseValue $js "t.a=`"" "`"";        
}

function StartSession()
{
    $empty = DoGet "https://twitter.com" ""
    
    $global:pageAuthToken = ParseValue $empty "<input type=`"hidden`" value=`"" "`" name=`"authenticity_token`""
    $global:guestId = ParseValue $global:strCookies "guest_id=" ";"
    $global:session = ParseValue $global:strCookies "_twitter_sess=" ";"
}

StartSession

$global:username = Read-Host 'What is your twitter username?'
$password = Read-Host 'What is your twitter password?'

$createLists = $false;
$strCreateList = Read-Host 'Create lists? (y/n)?'

if ($strCreateList.ToLower() -eq "y")
{
    $createLists = $true;

    $listMode = Read-Host 'List mode? (private/public)?'

    #just to be safe :)
    if ($listMode.ToLower() -ne "public")
    {
        $listMode = "private";
    }
}

Login $global:username $password;

if (!$global:loginAuthToken)
{
    write-host "Bad username\password" -ForegroundColor Red
    exit
}

<#

$ids = get-content "DirectMessageList.txt";
$message = get-content "DirectMessageMessage.txt";

foreach($id in $ids)
{
    SendDirectMessage $id $message;
}

$clear = read-host "Would you like to clear old non-tweeted accounts (y/n)?"

if ($clear.tolower() -eq "y")
{
    $months = read-host "How many months back (6)?"

    if ($months)
    {
        $ht = GetFollowers $global:username;
        RemoveFollowersByTweetDate $ht $(30 * $months);
    }
}
#>

while($true)
{
    write-host "Available mvp types:"

    $types = @("All", "Regional Director", "AI", "Access","Business Solutions","Cloud and Datacenter Management","Data Platform","Enterprise Mobility","Excel","Microsoft Azure","Office Development","Office Servers and Services","OneNote","Outlook","PowerPoint","Project","Visio", "Visual Studio and Development Technologies","Windows and Devices for IT","Windows Development", "Word")

    foreach ($type in $types)
    {
        write-host "`t$type" -ForegroundColor Green;
    }

    $type = read-host "Please enter the MVP type you'd like to follow"

    if ($type.tolower() -eq "all")
    {
        foreach($t in $types)
        {
            if ($t -eq "All")
            {
                continue;
            }        

            CheckMvpType $t $createLists $listMode;
        }
    }
    else
    {
        CheckMvpType $type $createLists $listMode;
    }
}