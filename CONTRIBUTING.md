## How to join MDATP community on GitHub without being GitHub-Ninja

![logo](https://raw.githubusercontent.com/microsoft/MicrosoftDefenderATP-API-Python/master/for%20contribution%20guide/logo.png?token=ANGTEKWLD7NBMS7S6NF6YZC5RNXLO)

In this article I am going to guide you how you can join MDATP community to use the experience of others and contribute from your own experience.

I will try to make that guide as simple as possible so all you need to be a part of the community is an internet connection and a GitHub account. I will use only GitHub website during all guide, so to be an active community member you don’t need to install anything, know how to code or run mysterious commands in your console.

So, let’s start:

* In the first part of this guide, I will briefly explain the contribution process.
* In the second part, I will demonstrate the contribution process using GitHub website.

***Contribution process:***

MDATP's community store its users' contribution on GitHub repositories. The contribution could be a simple text (like Advanced Hunting query), a PowerShell script (like in WDATP API and LiveResponse scripts) and even files like in PowerBI and Microsoft Flow.

To add your contribution to those repositories you need to create a branch of the repository where all your contributions will be temporarily stored until you decide you are ready to merge your contribution with the main repository.

When you are ready to share your contribution, you need to create a pull request which is the way to gather changes together and request the community managers to merge the changes with the main repository.

The pull request contains the differences from the origin branch, and it allows you, the manager, and even other community members to open a discussion about your contribution. 

**Part 1: A flow of the contribution process:**

![flow](https://raw.githubusercontent.com/microsoft/MicrosoftDefenderATP-API-Python/master/for%20contribution%20guide/process.png?token=ANGTEKXFUS2ILS5GW3LXZS25RNXRE)


**Part 2: Demonstration of the contribution process using GitHub website**

For this demonstrate I will contribute a new Advance Hunting query to “WDATP-Advanced-Hunting” repository.  For the demo, I will add a query to find how many unique machines have executed process called psexe.exe with system privilege across my organization.

so, I opened Windows Defender ATP Portal and navigate to the advanced hunting page where I’ve created and tested the query I want to contribute:

```
ProcessCreationEvents 
| where EventTime > ago(7d) 
| where FileName == "psexec.exe"
| where ProcessCommandLine contains "-s " or ProcessCommandLine contains "/s "
| distinct ComputerName
```

After testing the query I’ve decided that it’s awesome and I want to share it with the community.

Step 1 – create a branch from the production branch
1.	Open GitHub and find the microsoft/WindowsDefenderATP-Hunting-Queries
2.	Navigate to the folder where you want to create the new query’s file. (for example: General queries)
3.	Press “Create new file” button.

![create new file](https://raw.githubusercontent.com/microsoft/MicrosoftDefenderATP-API-Python/master/for%20contribution%20guide/create%20new%20file.png?token=ANGTEKR3LOKSROX7QS6UPX25RNXTG)

4.	Give your new file a name. like “psexec elevation to system.txt”
5.	Paste you query in the “Edit new file” textbox.
6.	In the propose new file section add a title and a justification for your change.

![propose new file](https://raw.githubusercontent.com/microsoft/MicrosoftDefenderATP-API-Python/master/for%20contribution%20guide/edit%20new%20file.png?token=ANGTEKRWPWZDTEFWIRCWQWC5RNXY6)

7.	Press “propose new file” button.

Pressing the button will automatically create a branch with your changes (the default name for the new branch is “patch-1”). In the next screen you can review your changes and you can press “Create pull request” button to create a pull request and propose merge your changes with main repository.

![create pull](https://raw.githubusercontent.com/microsoft/MicrosoftDefenderATP-API-Python/master/for%20contribution%20guide/create%20pull.png?token=ANGTEKUP7KPJS2Q5V7IZKAC5RNX4M)

Pressing the “Create pull request” button will create a pull request with all the changes in the new temporary branch and you could add title and justification for your change before submit the pull request.

![create pull 2](https://raw.githubusercontent.com/microsoft/MicrosoftDefenderATP-API-Python/master/for%20contribution%20guide/create%20pull%202.png?token=ANGTEKRNYT7WNSIELIANDHC5RNX52)

That's it. Once the community managers will approve your pull request, all your changes will be merged with the main repository.

I chose to demonstrate on the WindowsDefenderATP-Hunting-Queries which are contains text files with advanced hunting queries. In the same way, you can add PS1 files (PowerShell files) for LiveResponse or API repositories. All from GitHub website without one line of code or command line.

### Important note!!!!

MDATP’s GitHub repositories are under Microsoft open code license. Therefore, when you push your changes to one of our repositories you will get a notification to agree to CLA (Contribute License Agreement) if you didn’t approve it before. That agreement means you are agreeing to contribute your changes to the open-source project so everyone can use it.

Once you commit your pull request, if you required to sign on CLA you will see the following notification under your pull request:

![final 1](https://raw.githubusercontent.com/microsoft/MicrosoftDefenderATP-API-Python/master/for%20contribution%20guide/end%201.png?token=ANGTEKV7MOCHUDNQUI4DAYK5RNYCW)

Once you will sign you will see the following notification:

![final 2](https://raw.githubusercontent.com/microsoft/MicrosoftDefenderATP-API-Python/master/for%20contribution%20guide/end%202.png?token=ANGTEKQBSHRSW5FLY5LRHHS5RNYFM)

Happy contribution,

@Haim Goldshtein, security software engineer, Windows Defender ATP  
