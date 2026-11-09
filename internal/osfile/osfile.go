// Package osfile opens local files the way an SMB server needs them opened.
//
// Clients rename and delete files that they, or other clients, still hold
// open; SMB share modes decide whether that is allowed, and the server keeps
// track of them itself. On Unix any open file can be renamed or unlinked. On
// Windows os.OpenFile leaves out FILE_SHARE_DELETE, so the same rename fails
// with a sharing violation; Open asks for it.
package osfile
