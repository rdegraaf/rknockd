#include <vector>
#include <list>
#include <string>
#include <iostream>
#include <stdexcept>
#include <cstdint>
#include <tr1/unordered_map>
#include "common.h"

// Note: this implementation doesn't allow more than one result at a time


class UninitializedException : public std::runtime_error
{
  public:
    UninitializedException(const std::string& s);
};

template<typename CharType, typename MatchType>
class ACTree
{
  public:
    class ACNode
    {   
        typedef std::tr1::unordered_map<CharType, ACNode*> TransitionsType;
        const MatchType* match;
        TransitionsType transitions;
        ACNode* failure;
        ACNode();
        friend class ACTree;
    };
    ACTree();
    ~ACTree();
    void addString(const std::vector<CharType>& str, const MatchType& match);
    void compile();
    const ACNode* getInitialState() const;
    const MatchType* search(CharType ch, const ACNode*& node) const;

  private:
    typedef std::vector<CharType> ACString;
    std::list<ACNode> tree;
    bool dirty;

    
};

UninitializedException::UninitializedException(const std::string& s)
: runtime_error(s)
{}


template <typename CharType, typename MatchType>
ACTree<CharType, MatchType>::ACNode::ACNode()
: match(NULL), transitions(), failure(NULL)
{}

template <typename CharType, typename MatchType>
ACTree<CharType, MatchType>::ACTree()
: tree(), dirty(false)
{
    ACNode node;
    tree.push_back(node);
    tree.begin()->failure = &(*tree.begin());
}

template <typename CharType, typename MatchType>
ACTree<CharType, MatchType>::~ACTree()
{}

template <typename CharType, typename MatchType>
void
ACTree<CharType, MatchType>::addString(const std::vector<CharType>& str, const MatchType& match)
{
    ACNode* cur;
    ACNode* next = &(*tree.begin());
    typename ACNode::TransitionsType::iterator transition;
    
    for (typename ACString::const_iterator i=str.begin(); i!=str.end(); ++i)
    {
        cur = next;
        
        transition = cur->transitions.find(*i);
        if (transition == cur->transitions.end())
        {
            // we don't have this character; add it
            ACNode node;
            tree.push_back(node);
            next = &(*(--tree.end()));
            cur->transitions.insert(std::pair<CharType, ACNode*>(*i, next));
std::cout << "inserting " << *i << " as " << (unsigned)next << std::endl;
        }
        else
        {
            // we already have this character; move on to the next
            next = transition->second;
std::cout << *i << " already exists" << std::endl;
        }
    }

    // we're now at the end node for this string
    // fail silently if there's already a match here
    if (next->match == NULL)
        next->match = &match;
    
    // don't allow searches until the failures have been updated again
    dirty = true;
}

template <typename CharType, typename MatchType>
void
ACTree<CharType, MatchType>::compile()
{
    std::list<ACNode*> queue;
    ACNode* cur = &(*tree.begin());
    ACNode* state;
    typename ACNode::TransitionsType::iterator tmp;
    
    for (typename ACNode::TransitionsType::iterator i = cur->transitions.begin();
         i != cur->transitions.end(); ++i)
    {
        queue.push_back(i->second);
        i->second->failure = cur;
    }
    
    while (queue.begin() != queue.end())
    {
        cur = *queue.begin();
        queue.pop_front();

        for (typename ACNode::TransitionsType::iterator i = cur->transitions.begin();
             i != cur->transitions.end(); ++i)
        {
            queue.push_back(i->second);
            state = cur->failure;
            
            while ((tmp = state->transitions.find(i->first)) == state->transitions.end())
            {
                if (state == state->failure) // prevent looping in the start state
                    break;
                state = state->failure;
            }
            if (tmp == state->transitions.end())
                i->second->failure = &(*tree.begin());
            else
                i->second->failure = tmp->second;
            
            // add to i->second's matches here
        }
    }
    
    // allow users to search now
    dirty = false;
}

template <typename CharType, typename MatchType>
const typename ACTree<CharType, MatchType>::ACNode* 
ACTree<CharType, MatchType>::getInitialState() const
{
    return &(*tree.begin());
}


template <typename CharType, typename MatchType>
const MatchType*
ACTree<CharType, MatchType>::search(CharType ch, const ACNode*& state) const THROW((UninitializedException))
{
    typename ACNode::TransitionsType::const_iterator tmp;

    if (dirty == true)
        throw UninitializedException("You need to call 'compile' before searching");

std::cout << "searching " << ch << " from " << (unsigned)state << std::endl;

    while ((tmp = state->transitions.find(ch)) == state->transitions.end())
    {

std::cout << "  failure" << std::endl;

        if (state == state->failure) // prevent looping in the start state
            break;
        state = state->failure;
    }
    if (tmp != state->transitions.end())
        state = tmp->second;

if (tmp != state->transitions.end())
std::cout << "  found " << tmp->first << std::endl;    
if (state->match != NULL)
std::cout << "  matched " << *(state->match) << std::endl;

    return state->match;
}

int main()
{
    ACTree<uint16_t, std::string> tree;
    const ACTree<uint16_t, std::string>::ACNode* state;
    const std::string* str;
    std::vector<uint16_t> vec1;
    std::vector<uint16_t> vec2;
    std::vector<uint16_t> vec3;
    std::string str1 = "123";
    std::string str2 = "124";
    std::string str3 = "312";

    vec1.push_back(1);
    vec1.push_back(2);
    vec1.push_back(3);
    vec2.push_back(1);
    vec2.push_back(2);
    vec2.push_back(4);
    vec3.push_back(3);
    vec3.push_back(1);
    vec3.push_back(2);

    tree.addString(vec1, str1);
    tree.addString(vec2, str2);
    tree.addString(vec3, str3);
    tree.compile();

    state = tree.getInitialState();
    str = tree.search(1, state);
    str = tree.search(2, state);
    str = tree.search(3, state); // should match 123
    str = tree.search(1, state);
    str = tree.search(2, state); // should match 321
    str = tree.search(5, state);
    str = tree.search(1, state);
    str = tree.search(2, state);
    str = tree.search(1, state);
    str = tree.search(2, state);
    str = tree.search(4, state); // should match 124
    str = tree.search(1, state);
    str = tree.search(3, state);
    str = tree.search(3, state);
    str = tree.search(1, state);
    str = tree.search(5, state);

    
    if (str != NULL)
        std::cout << "found string " << *str << std::endl;
    return 0;
}
    
