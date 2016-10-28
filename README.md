Better permission or bperm is a rewrite of project permission2, found at
https://github.com/xyproto/permissions2 , I wasn't personally satisfied with the
implementation. So I decided to fork it and rewrite it, I needed it to work with
any database, the current original project uses a different project for different
database backend... I needed it to be database plug and play, so that changing 
or adding databases backend is easy and not painful. The dependency from 
the package where the interfaces used to be defined has been deleted as 
well as the need for them. Userstate file has been greatly simplified. To use
only a database and not any auxiliary data structure.
Currently there is only a backend implementation and it's the google-cloud datastore.
And the package wasn't tested. Forked https://github.com/xyproto/cookie as well.

TODO
milestones:
	- finish the complete rewrite 
	- hit 90% test coverage

NOTES:
	- Thanks to the original writer anyway.
